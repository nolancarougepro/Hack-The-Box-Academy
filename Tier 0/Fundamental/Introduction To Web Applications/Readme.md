## Introduction : 

![[Intro.png]]

## Web Application Layout : 

![[one-server-arch.jpg]]![[client-server-model.jpg]]![[many-server-one-db-arch.jpg]]![[many-server-many-db-arch.jpg]]![[many-server-one-db-arch.jpg]]

## Front End vs. Back End : 

![[frontend-components.jpg]]
![[backend-server.jpg]]
![[Mistake1.png]]![[Mistake2.png]]
![[Vulnerability.png]]

## HTML : 

![[Encoding Char.png]]

## JavaScript : 
# Sensitive Data Exposure : 

Always look at the source code, you can find interesting data.

## HTML Injection : 

If no input sanitization is in place, this is potentially an easy target for `HTML Injection` and `Cross-Site Scripting (XSS)` attacks.
## Cross-Site Scripting (XSS) : 

XSS vulnerabilities are a type of HTML Injection, for XSS it is JavaScript code injection. There are several types of XSS.

![[XSS Types.png]]

DOM XSS JavaScript : 
```javascript
#"><img src=/ onerror=alert(document.cookie)>
```

## Cross-Site Request Forgery (CSRF) : 
![[CSRF.png]]
How to protect yourself from attacks?

![[Prevent.png]]

## Back End Servers : 

The back end server contains the other 3 back end components :
- `Web Server`
- `Database`
- `Development Framework`

![[Servers Type.png]]

## Web Servers : 

![[Code1.png]]![[Code2.png]]

Apache (Apple, Adobe, Baidu).
Nginx (Google, Facebook, X, Cisco, Intel ...).
IIS (Microsoft, Office365, Skype, StackOverflow ...).

## Databases : 

Relational (SQL) : 

![[web_apps_relational_db.jpg]]
![[SQLType.png]]

Non-relational (NoSQL) : (stores data in JSON or XML)

![[web_apps_non-relational_db.jpg]]
![[NoSQLType.png]]

## Development Frameworks & APIs : 

- [Laravel](https://laravel.com/) (`PHP`): usually used by startups and smaller companies, as it is powerful yet easy to develop for.
- [Express](https://expressjs.com/) (`Node.JS`): used by `PayPal`, `Yahoo`, `Uber`, `IBM`, and `MySpace`.
- [Django](https://www.djangoproject.com/) (`Python`): used by `Google`, `YouTube`, `Instagram`, `Mozilla`, and `Pinterest`.
- [Rails](https://rubyonrails.org/) (`Ruby`): used by `GitHub`, `Hulu`, `Twitch`, `Airbnb`, and even `Twitter` in the past.

## Common Web Vulnerabilities : 

- Broken Authentication/Access Control.
- Malicious File Upload.
- Command Injection.
- SQL Injection (SQLi).

## Public Vulnerabilities : 

![[CVSS.png]]