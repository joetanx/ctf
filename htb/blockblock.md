![image](https://github.com/user-attachments/assets/bc1c14a9-1796-480a-98ec-41be868a080e)

## 1. Recon

### 1.1. Port Scan `nmap`

```console
root@kali:~# nmap -Pn -p- -A 10.10.11.43
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-01 20:50 +08
Nmap scan report for 10.10.11.43
Host is up (0.0046s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.7 (protocol 2.0)
| ssh-hostkey:
|   256 d6:31:91:f6:8b:95:11:2a:73:7f:ed:ae:a5:c1:45:73 (ECDSA)
|_  256 f2:ad:6e:f1:e3:89:38:98:75:31:49:7a:93:60:07:92 (ED25519)
80/tcp   open  http    Werkzeug/3.0.3 Python/3.12.3
|_http-title:          Home  - DBLC
|_http-server-header: Werkzeug/3.0.3 Python/3.12.3
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.12.3
|     Date: Wed, 01 Jan 2025 12:35:48 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 275864
|     Access-Control-Allow-Origin: http://0.0.0.0/
|     Access-Control-Allow-Headers: Content-Type,Authorization
|     Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <title>
|     Home - DBLC
|     </title>
|     <link rel="stylesheet" href="/assets/nav-bar.css">
|     </head>
|     <body>
|     <!-- <main> -->
|     <meta charset=utf-8>
|     <meta name=viewport content="width=device-width, initial-scale=1">
|     <style>
|     :after,
|     :before {
|     box-sizing: border-box;
|     border: 0 solid #e5e7eb
|     :after,
|     :before {
|     --tw-content: ""
|     :host,
|     html {
|     line-height: 1.5;
|   HTTPOptions:
|     HTTP/1.1 500 INTERNAL SERVER ERROR
|     Server: Werkzeug/3.0.3 Python/3.12.3
|     Date: Wed, 01 Jan 2025 12:35:48 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 265
|     Access-Control-Allow-Origin: http://0.0.0.0/
|     Access-Control-Allow-Headers: Content-Type,Authorization
|     Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>500 Internal Server Error</title>
|     <h1>Internal Server Error</h1>
|_    <p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
8545/tcp open  unknown
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 400 BAD REQUEST
|     Server: Werkzeug/3.0.3 Python/3.12.3
|     Date: Wed, 01 Jan 2025 12:35:48 GMT
|     content-type: text/plain; charset=utf-8
|     Content-Length: 43
|     vary: origin, access-control-request-method, access-control-request-headers
|     access-control-allow-origin: *
|     date: Wed, 01 Jan 2025 12:35:48 GMT
|     Connection: close
|     Connection header did not include 'upgrade'
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.12.3
|     Date: Wed, 01 Jan 2025 12:35:48 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, POST, OPTIONS, GET
|     Access-Control-Allow-Origin: *
|     Content-Length: 0
|     Connection: close
|   Help:
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('HELP').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|     </html>
|   RTSPRequest:
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
⋮
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=1/1%OT=22%CT=1%CU=38018%PV=Y%DS=2%DC=T%G=Y%TM=67753
OS:A8D%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)O
OS:PS(O1=M552ST11NW7%O2=M552ST11NW7%O3=M552NNT11NW7%O4=M552ST11NW7%O5=M552S
OS:T11NW7%O6=M552ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)E
OS:CN(R=Y%DF=Y%T=40%W=FAF0%O=M552NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F
OS:=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5
OS:(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z
OS:%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=
OS:N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%
OS:CD=S)

Network Distance: 2 hops

TRACEROUTE (using port 143/tcp)
HOP RTT     ADDRESS
1   4.89 ms 10.10.14.1
2   4.97 ms 10.10.11.43

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 108.33 seconds
```
