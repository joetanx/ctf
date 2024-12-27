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
