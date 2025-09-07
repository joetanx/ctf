## Discovering and visualizing relationships between Active Directory entities with BloodHound

BloodHound generate graphs using `neo4j` graph database to provide visualization of relationships between Active Directory entities

## 1. Setup BloodHound

Install BloodHound package:

```sh
apt update && apt -y install bloodhound
```

### 1.1. Run BloodHound configuration script

> [!Tip]
>
> The neo4j database listens on localhost by default, with the `dbms.default_listen_address=0.0.0.0` line in `/etc/neo4j/neo4j.conf` commented off
>
> Uncomment the configuration line to listen on all IPs (if needed):
>
> ```sh
> sed -i '/default_listen_address/s/#//' /etc/neo4j/neo4j.conf
> ```
>
> Note that `bloodhound-setup` will still try to open `http://localhost:7474/` even when the listening address is changed to `0.0.0.0`, just ignore it

Run `bloodhound-setup`:

```console
root@kali:~# bloodhound-setup

 [*] Starting PostgreSQL service

 [*] Creating Database

 Creating database user

 Creating database
ALTER ROLE

 [*] Starting neo4j
Neo4j is running at pid 2209

 [i] You need to change the default password for neo4j
     Default credentials are user:neo4j password:neo4j

 [!] IMPORTANT: Once you have setup the new password, please update /etc/bhapi/bhapi.json with the new password before running bloodhound

 opening http://localhost:7474/
```

### 1.2. Setup neo4j password

Login with the default credentials `neo4j`/`neo4j`:

![](https://github.com/user-attachments/assets/32f9ac34-ebc4-4ae0-ab7c-2ec183da82f3)

Mandated password change after the first login:

![](https://github.com/user-attachments/assets/8422bafa-99d1-46cf-9b9d-19c8a6420cad)

Done with neo4j database:

![](https://github.com/user-attachments/assets/7f63fc15-26c6-4d85-bed5-f5ed7c5947e0)

### 1.3. Run BloodHound

Update the neo4j password in `/etc/bhapi/bhapi.json`:

```sh
sed -i 's/"secret": "neo4j"/"secret": "password"/' /etc/bhapi/bhapi.json
```

> [!Tip]
> 
> Bloodhound listens on 127.0.0.1 by default, add `bind_addr` and `root_url` into `/etc/bhapi/bhapi.json` to change it:
>
> ```sh
> sed -i '2i\  "root_url": "http://kali:8080/",' /etc/bhapi/bhapi.json
> sed -i '2i\  "bind_addr": "0.0.0.0:8080",' /etc/bhapi/bhapi.json
> ```
>
> Note that `bloodhound` will still try to open `http://localhost:8080/` even when the listening address is changed to `0.0.0.0`, just ignore it

Run `bloodhound`':

```console
root@kali:~# bloodhound

 Starting neo4j
Neo4j is running at pid 2357

 Bloodhound will start

 IMPORTANT: It will take time, please wait...
⋮
{"time":"2025-09-07T10:14:20.651824503+08:00","level":"INFO","message":"########################################"}
{"time":"2025-09-07T10:14:20.651847051+08:00","level":"INFO","message":"#                                      #"}
{"time":"2025-09-07T10:14:20.651853711+08:00","level":"INFO","message":"# Initial Password Set To:    admin    #"}
{"time":"2025-09-07T10:14:20.651859191+08:00","level":"INFO","message":"#                                      #"}
{"time":"2025-09-07T10:14:20.65186257+08:00","level":"INFO","message":"########################################"}
⋮
 opening http://127.0.0.1:8080
```

Login with the default `admin`/`admin`:

![](https://github.com/user-attachments/assets/8acd22ea-84cc-4dbf-bd22-e43b0e4dbac7)

Finish the mandated password change:

![](https://github.com/user-attachments/assets/a3259d42-c49a-4dda-baa6-4b269eb1fe86)

And get access to the UI:

![](https://github.com/user-attachments/assets/2d134d3b-869c-4ccb-8734-38f4bf03adb3)

Bloodhound now has a dark mode:

![](https://github.com/user-attachments/assets/b97eab9e-81b5-4374-9b6d-e5327a36d5f2)

## 2. Gathering Active Directory data

### 2.1. Retrieve domain information

There are several methods to retrieve domain information, including [SharpHound](https://github.com/SpecterOps/SharpHound)

If the domain user and password is available, retrieving with `bloodhound.py` from Kali is straightforward

```console
root@kali:~# bloodhound-python -d lab.vx -u joe -p Micro123 -ns 192.168.17.20 -c all --dns-tcp --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: lab.vx
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.lab.vx
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.lab.vx
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 16 users
INFO: Found 60 groups
INFO: Found 2 gpos
INFO: Found 5 ous
INFO: Found 24 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.lab.vx
INFO: Done in 00M 00S
INFO: Compressing output into 20250907103324_bloodhound.zip
```

### 2.2. Load into BloodHound

Go to `File Ingest` and select `Upload File(s)`:

![](https://github.com/user-attachments/assets/ac4f6630-540b-450f-ad6e-cf9d56f9f904)

Select the zip file generated by `bloodhound-python` and `Upload`:

![](https://github.com/user-attachments/assets/73b395f5-4f3f-4c63-96ad-949be6fcdfb5)

![](https://github.com/user-attachments/assets/a18c35dd-fb43-4e00-af11-9be073734eb8)

The ingestion would take a short while and the data would be available in `Explore` when the status changes from `Ingesting` to `Complete`:

![](https://github.com/user-attachments/assets/0f3a7d4d-4d78-4e26-b7c5-418ae3006cc3)

![](https://github.com/user-attachments/assets/6b887dec-60e1-4191-bd1b-c77986581ce6)

### 2.3. Clearing sessions and database

The database stores all bloodbound packages uploaded

To start anew with a fresh workbench, select the data to delete under `Database Management`

![image](https://github.com/user-attachments/assets/07a8c265-d9e6-42ef-953f-b965543e40fd)

![](https://github.com/user-attachments/assets/66168c0e-51bc-48ac-91f8-9b1b9a73c48d)

![](https://github.com/user-attachments/assets/7b7abb22-0bf0-4c00-a96d-912a0ffcb1e4)

## 3. Interesting BloodHound queries

> [!Tip]
>
> ### Node labels
>
> Pressing `Ctrl` toggles showing and hiding node labels, this can be useful to see all the node labels
>
> ![image](https://github.com/user-attachments/assets/8271412f-92d6-40f2-b091-e4a9297c87f4)
> 
> ![image](https://github.com/user-attachments/assets/2c9af113-163e-4828-ac17-8438b3b90cac)
>
> If there are too many nodes to show label, showing node labels can hit the node label threshold
>
> ![image](https://github.com/user-attachments/assets/398c4970-9f2a-4b17-8070-92188039bb64)
>
> This can be adjusted in settings:
>
> ![image](https://github.com/user-attachments/assets/80a873f5-a0dc-4e95-82f5-6e21deb68183)

### 3.1. Find all Domain Admins

![image](https://github.com/user-attachments/assets/81ff2072-01b6-4740-8441-bdf8c5ddf638)

### 3.2. Find Shortest Paths to Domain Admins

![image](https://github.com/user-attachments/assets/5c8db6ae-1df8-4024-adad-243038e3788b)

### 3.3. Find AS-REP Roastable Users (DontReqPreAuth)

There are no AS-REP roastable users. Hence, no data returned from query.

![image](https://github.com/user-attachments/assets/31c98a3b-c8f4-4ea6-9252-eb2e47d8381b)

### 3.4. Find Principals with DCSync Rights

![image](https://github.com/user-attachments/assets/34e6f9be-2ebb-4807-b191-402c02e9875a)

### 3.5. List all Kerberoastable Accounts

![image](https://github.com/user-attachments/assets/4a2a1f35-140c-4c5d-a08e-89f0231d3132)

## 4. Investigating account access examples

### 4.1. Example 1: account is a Domain Admin

Search for the account:

![image](https://github.com/user-attachments/assets/1d941a5c-2c9c-44bc-9927-a71281544d81)

Select the node and select `Reachable High Value Targets`

![image](https://github.com/user-attachments/assets/c610ad11-f34a-4eb0-ab48-173c57c7f709)

When the account is a Domain Admin, the graph is straightforward since it's just a member of the `Domain Admins` group

![image](https://github.com/user-attachments/assets/1ab3fac1-ef70-48a4-9305-293d40c88b61)

### 4.2. Example 2: account is not directly privileged, but is part of a chain of permissions

Search for the account:

![image](https://github.com/user-attachments/assets/ad5cdd66-4e94-4b8d-be13-ada5f249ae66)

Select the node and select `Reachable High Value Targets`

![image](https://github.com/user-attachments/assets/faf7cfb7-de08-4b20-ad62-83eec9d46d73)

The account `d.anderson` in this example is not privileged, but is part of a chain of permissions to gaining PSRemote access to the domain controller

![image](https://github.com/user-attachments/assets/93ebb8ac-5122-44bb-a24d-f7d2cac60183)

> [!Tip]
>
> Hover on an edge and right-click to get explanation on the edge
>
> ![image](https://github.com/user-attachments/assets/629da73e-0bb5-4aca-9046-bb0199c65d76)

GenericAll:

![image](https://github.com/user-attachments/assets/becb4844-1db5-4c64-ad4d-36aa3072af3c)

AddSelf:

![image](https://github.com/user-attachments/assets/b1a359cb-24c9-47ba-8fec-aef1cb3c1224)

ForceChangePassword:

![image](https://github.com/user-attachments/assets/98661911-ea50-48ca-8397-cfa9eee94c40)

CanPSRemote:

![image](https://github.com/user-attachments/assets/9928a04e-c286-49bf-85e2-213925a2daea)
