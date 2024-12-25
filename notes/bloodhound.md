## Discovering and visualizing relationships between Active Directory entities with BloodHound

BloodHound generate graphs using `neo4j` graph database to provide visualization of relationships between Active Directory entities

## 1. Setup BloodHound

### 1.1. Install BloodHound package

```sh
apt update
apt -y install bloodhound
```

### 1.2. Initialize neo4j database

By default: the neo4j database listens on localhost, and the `dbms.default_listen_address=0.0.0.0` line in `/etc/neo4j/neo4j.conf` is commented off

Uncomment the configuration line to listen on all IPs (if needed):

```sh
sed -i '/default_listen_address/s/#//' /etc/neo4j/neo4j.conf
```

Start neo4j:
(the `&` runs `neo4j console` as a background job)

```console
root@kali:~# neo4j console &
[1] 1891

Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Directories in use:
home:         /usr/share/neo4j
config:       /usr/share/neo4j/conf
logs:         /etc/neo4j/logs
plugins:      /usr/share/neo4j/plugins
import:       /usr/share/neo4j/import
data:         /etc/neo4j/data
certificates: /usr/share/neo4j/certificates
licenses:     /usr/share/neo4j/licenses
run:          /var/lib/neo4j/run
Starting Neo4j.
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
2024-12-24 00:38:53.673+0000 INFO  Starting...
2024-12-24 00:38:53.942+0000 INFO  This instance is ServerId{4fb5f8d2} (4fb5f8d2-58eb-4847-9e3a-cf8143cb8bef)
2024-12-24 00:38:54.717+0000 INFO  ======== Neo4j 4.4.26 ========
2024-12-24 00:38:55.872+0000 INFO  Initializing system graph model for component 'security-users' with version -1 and status UNINITIALIZED
2024-12-24 00:38:55.878+0000 INFO  Setting up initial user from defaults: neo4j
2024-12-24 00:38:55.879+0000 INFO  Creating new user 'neo4j' (passwordChangeRequired=true, suspended=false)
2024-12-24 00:38:55.885+0000 INFO  Setting version for 'security-users' to 3
2024-12-24 00:38:55.887+0000 INFO  After initialization of system graph model component 'security-users' have version 3 and status CURRENT
2024-12-24 00:38:55.889+0000 INFO  Performing postInitialization step for component 'security-users' with version 3 and status CURRENT
2024-12-24 00:38:56.165+0000 INFO  Bolt enabled on [0:0:0:0:0:0:0:0%0]:7687.
2024-12-24 00:38:56.716+0000 INFO  Remote interface available at http://localhost:7474/
2024-12-24 00:38:56.718+0000 INFO  id: 94690E54A6CC3D152DCD3D362CF1E57BDA06E7BF02AC5F0E8C9C239837D4586A
2024-12-24 00:38:56.718+0000 INFO  name: system
2024-12-24 00:38:56.718+0000 INFO  creationDate: 2024-12-24T00:38:55.085Z
2024-12-24 00:38:56.719+0000 INFO  Started.
```

Login with the default credentials `neo4j`/`neo4j`:

![image](https://github.com/user-attachments/assets/163728d3-5e75-4474-b133-201dda5c50bf)

Mandated password change after the first login:

![image](https://github.com/user-attachments/assets/e7477ce2-539c-4541-9fb4-6e2b63f0705d)

Done with neo4j database:

![image](https://github.com/user-attachments/assets/15d2c35c-0046-4d9d-8a32-6f919a8a6e4a)

## 2. Gathering Active Directory data

### 2.1. Retrieve domain information

There are several methods to retrieve domain information, including [SharpHound](https://github.com/SpecterOps/SharpHound)

If the domain user and password is available, retrieving with `bloodhound.py` from Kali is straightforward

```console
root@kali:~# bloodhound-python -d net.vx -u joe -p Forti123 -c all --dns-tcp --zip
INFO: Found AD domain: net.vx
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.net.vx
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.net.vx
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 16 users
INFO: Found 60 groups
INFO: Found 2 gpos
INFO: Found 6 ous
INFO: Found 24 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.net.vx
INFO: Done in 00M 00S
INFO: Compressing output into 20241224141256_bloodhound.zip
```

### 2.2. Load into BloodHound

Open BloodHound from apps list:

![image](https://github.com/user-attachments/assets/5048c139-23c8-45bb-86de-57c75c2bf353)

Login with credentials set from the neo4j initialization:

![image](https://github.com/user-attachments/assets/11bbbb2f-70bc-4e12-a176-3ca21e81f041)

Select `Upload Data` from the list of buttons on the right:

![image](https://github.com/user-attachments/assets/50cd1781-0f3d-4292-b4ce-8f8df5828948)

Select the zip package from `bloodhound.py`:

![image](https://github.com/user-attachments/assets/06e0fe59-c123-4378-91cf-1fe043011a10)

![image](https://github.com/user-attachments/assets/3b8721d0-4bc7-4353-8e3c-b3973565d7cd)


## 3. Interesting BloodHound queries

### 3.1. Find all Domain Admins

![image](https://github.com/user-attachments/assets/81ff2072-01b6-4740-8441-bdf8c5ddf638)

### 3.2. Find Shortest Paths to Domain Admins

![image](https://github.com/user-attachments/assets/5c8db6ae-1df8-4024-adad-243038e3788b)

### 3.3. Find AS-REP Roastable Users (DontReqPreAuth)

There are no AS-REP roastable users. Hence, no data returned from query.

![image](https://github.com/user-attachments/assets/ee1fcdc9-2ead-46a1-8678-c87ba14d4adf)

### 3.4. Find Principals with DCSync Rights

![image](https://github.com/user-attachments/assets/34e6f9be-2ebb-4807-b191-402c02e9875a)

### 3.5. List all Kerberoastable Accounts

![image](https://github.com/user-attachments/assets/4a2a1f35-140c-4c5d-a08e-89f0231d3132)
