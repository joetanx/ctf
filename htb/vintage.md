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

### 2.3. Active Directory discovery: Bloodhound

Let's figure out if there are any viable lateral movement pathways

#### 2.3.1. Generating bloodhound packages

```console
root@kali:~# bloodhound-python -d vintage.htb -u P.Rosa -p Rosaisbest123 -ns 10.10.11.45 -c all  --dns-tcp --zip
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
INFO: Compressing output into 20241229164901_bloodhound.zip
```
