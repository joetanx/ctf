![](https://github.com/user-attachments/assets/8278069b-610a-4c6d-a7b6-101029e255af)

## 1. Recon

### 1.1. Port Scan `nmap`

Quick initial scan to find open ports:

```console
root@kali:~# nmap -sS -p- --min-rate 100000 -Pn 10.10.11.54
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-13 08:34 +08
Nmap scan report for 10.10.11.54
Host is up (0.013s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 1.53 seconds
```

Script and version scan on open ports:

```console
root@kali:~# nmap -Pn -p 22,80 -sCV 10.10.11.54
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-13 08:34 +08
Nmap scan report for 10.10.11.54
Host is up (0.0054s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey:
|   256 33:41:ed:0a:a5:1a:86:d0:cc:2a:a6:2b:8d:8d:b2:ad (ECDSA)
|_  256 04:ad:7e:ba:11:0e:e0:fb:d0:80:d3:24:c2:3e:2c:c5 (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.37 seconds
```

## 2. Exploring Roundcube Webmail

The web app is at `http://drip.htb/`:

```console
root@kali:~# curl 10.10.11.54
<meta http-equiv="refresh" content="0; url=http://drip.htb/" />
```

_Sign In_ links to `http://mail.drip.htb/`:

![](https://github.com/user-attachments/assets/4ee1c489-f446-4668-b63f-547648e37102)

Which is Roundcube Webmail:

![](https://github.com/user-attachments/assets/56f7f86b-5c0c-4bbb-a5fd-da7e6cb9c0ab)

_Sign Up_ links to account registration page:

![](https://github.com/user-attachments/assets/f36f0c12-8848-4a6e-b2bb-c50bee487843)

Register account and sign in:

![](https://github.com/user-attachments/assets/192c3faf-5147-419c-8c68-34acc4bb756c)
