![image](https://github.com/user-attachments/assets/cd7bacaf-d85d-47e2-9a67-b87c62e797d6)

## 1. Recon

### 1.1. Port Scan `nmap`

```console
root@kali:~# nmap -Pn -A 10.10.11.9
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-18 15:10 +08
Nmap scan report for 10.10.11.9
Host is up (0.0049s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE    SERVICE  VERSION
22/tcp   open     ssh      OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey:
|   256 e0:72:62:48:99:33:4f:fc:59:f8:6c:05:59:db:a7:7b (ECDSA)
|_  256 62:c6:35:7e:82:3e:b1:0f:9b:6f:5b:ea:fe:c5:85:9a (ED25519)
25/tcp   filtered smtp
80/tcp   open     http     nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: Did not follow redirect to http://magicgardens.htb/
5000/tcp open     ssl/http Docker Registry (API: 2.0)
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Not valid before: 2023-05-23T11:57:43
|_Not valid after:  2024-05-22T11:57:43
|_http-title: Site doesn't have a title.
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=12/18%OT=22%CT=1%CU=32226%PV=Y%DS=2%DC=T%G=Y%TM=676
OS:275B7%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A
OS:)OPS(O1=M552ST11NW7%O2=M552ST11NW7%O3=M552NNT11NW7%O4=M552ST11NW7%O5=M55
OS:2ST11NW7%O6=M552ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88
OS:)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M552NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+
OS:%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
OS:T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A
OS:=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%D
OS:F=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=4
OS:0%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT     ADDRESS
1   5.39 ms 10.10.14.1
2   5.51 ms 10.10.11.9

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.93 seconds
```

## 2. Exploring

### 2.1. `80`

![image](https://github.com/user-attachments/assets/400608ce-034c-44f4-9a57-5f63ecf4a9fa)

```console
root@kali:~# gobuster dir -u http://magicgardens.htb/ -b 403,404 -w /usr/share/dirb/wordlists/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://magicgardens.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 0] [--> /admin/]
/cart                 (Status: 301) [Size: 0] [--> /cart/]
/catalog              (Status: 301) [Size: 0] [--> /catalog/]
/check                (Status: 301) [Size: 0] [--> /check/]
/login                (Status: 301) [Size: 0] [--> /login/]
/logout               (Status: 301) [Size: 0] [--> /logout/]
/profile              (Status: 301) [Size: 0] [--> /profile/]
/register             (Status: 301) [Size: 0] [--> /register/]
/restore              (Status: 301) [Size: 0] [--> /restore/]
/search               (Status: 301) [Size: 0] [--> /search/]
/subscribe            (Status: 301) [Size: 0] [--> /subscribe/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```
