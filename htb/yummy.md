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
