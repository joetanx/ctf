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

### 1.2. Exploring

Add host records for easy navigation:

```
echo 10.10.11.24 ghost.htb DC01.ghost.htb core.ghost.htb federation.ghost.htb >> /etc/hosts
```

> [!Note]
>
> `ghost.htb`,  `DC01.ghost.htb` and `core.ghost.htb` are discovered from nmap scan above, `federation.ghost.htb` is found from exploring `core.ghost.htb` on `:8443` below

#### 1.2.1. `443`

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

#### 1.2.2. `8443`

`https://core.ghost.htb:8443/login`:

![image](https://github.com/user-attachments/assets/56541c72-13ef-4817-a799-b039cd843152)

`https://federation.ghost.htb/`:

![image](https://github.com/user-attachments/assets/12742a21-67fe-4694-a40b-b5a4fa13ed94)

#### 1.2.3. `8008`

Root page appears to be some kind of blog:

![image](https://github.com/user-attachments/assets/c944ad2d-ecdd-4de9-b11a-7502c77860e3)

Viewing the page source reveals some kind of id:

`<script src="/assets/built/source.js?v=718615e1f1"></script>`

![image](https://github.com/user-attachments/assets/50cd2b41-3f4d-4062-b293-ef38bd465c14)

`http-robots.txt` above found 5 disallowed entries, only `/ghost/` has a page, which is the ghost CMS login:

![image](https://github.com/user-attachments/assets/6dd4c0b5-a6ae-4a30-ac13-d99c9b151b1e)

### 1.3. Web enumeration

#### 1.3.1. Enumerate for pages

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

#### 1.3.2. Enumerate for domains

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

##### 1.3.2.1. Gitea

![image](https://github.com/user-attachments/assets/cbcec9e3-fb09-4d87-962f-a678bd4167b3)

![image](https://github.com/user-attachments/assets/444cbc2a-8b2d-4635-a19f-d7db54af7862)

![image](https://github.com/user-attachments/assets/5947dd59-d54d-4303-95c1-49edb124de4a)

##### 1.3.2.2. Intranet

![image](https://github.com/user-attachments/assets/79f3c49d-ce45-4d07-9361-0b3521e5699f)
