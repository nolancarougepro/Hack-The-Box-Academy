## Introduction : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/Intro.png)

## Web Application Layout : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/one-server-arch.jpg)
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/client-server-model.jpg)
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/many-server-one-db-arch.jpg)
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/many-server-many-db-arch.jpg)

## Front End vs. Back End : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/frontend-components.jpg)
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/backend-server.jpg)
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/Mistake1.png)
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/Mistake2.png)
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/Vulnerability.png)

## HTML : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/Encoding%20Char.png)

## JavaScript : 
# Sensitive Data Exposure : 

Always look at the source code, you can find interesting data.

## HTML Injection : 

If no input sanitization is in place, this is potentially an easy target for `HTML Injection` and `Cross-Site Scripting (XSS)` attacks.
## Cross-Site Scripting (XSS) : 

XSS vulnerabilities are a type of HTML Injection, for XSS it is JavaScript code injection. There are several types of XSS.

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/XSS%20Types.png)

DOM XSS JavaScript : 
```javascript
#"><img src=/ onerror=alert(document.cookie)>
```

## Cross-Site Request Forgery (CSRF) : 
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/CSRF.png)
How to protect yourself from attacks?

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/Prevent.png)

## Back End Servers : 

The back end server contains the other 3 back end components :
- `Web Server`
- `Database`
- `Development Framework`

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/Servers%20Type.png)

## Web Servers : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/Code1.png)
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/Code2.png)

Apache (Apple, Adobe, Baidu).
Nginx (Google, Facebook, X, Cisco, Intel ...).
IIS (Microsoft, Office365, Skype, StackOverflow ...).

## Databases : 

Relational (SQL) : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/web_apps_relational_db.jpg)
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/SQLType.png)

Non-relational (NoSQL) : (stores data in JSON or XML)

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/web_apps_non-relational_db.jpg)
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/NoSQLType.png)

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

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Introduction%20To%20Web%20Applications/Images/CVSS.png)
