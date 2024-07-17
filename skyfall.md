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

