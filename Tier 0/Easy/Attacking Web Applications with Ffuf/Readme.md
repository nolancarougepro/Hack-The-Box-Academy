## Introduction : 

The following topics will be discussed:
- Fuzzing for directories
- Fuzzing for files and extensions
- Identifying hidden vhosts
- Fuzzing for PHP parameters
- Fuzzing for parameter values

## Web Fuzzing : 

The term `fuzzing` refers to a testing technique that sends various types of user input to a certain interface to study how it would react.

## Directory Fuzzing : 

```shell
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://natation-pierrelatte.fr/FUZZ
```

## Page Fuzzing : 

We check if the blog folder does not contain hidden pages :
```shell
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://83.136.254.199:59118/blog/indexFUZZ
```

```shell
┌─[nolanc@parrot]─[~]
└──╼ $ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://83.136.254.199:59118/blog/indexFUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://83.136.254.199:59118/blog/indexFUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/web-extensions.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 403, Size: 282, Words: 20, Lines: 10, Duration: 3912ms]
    * FUZZ: .phps

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 4926ms]
    * FUZZ: .php

:: Progress: [41/41] :: Job [1/1] :: 8 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

Once we have found extensions (.php and .phps), we look where they lead :
```shell
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://83.136.254.199:59118/blog/FUZZ.php
```
## Recursive Fuzzing : 

To avoid doing as in the previous part, a command does both at the same time :
```shell
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://83.136.249.57:50425/FUZZ -recursion -recursion-depth 1 -e .php -v
```

## DNS Records : 

From time to time you have to do the DNS work by adding the server address with its IP in /etc/hosts.

## Sub-domain Fuzzing

A subdomain of `google.com` is for example `https://photos.google.com`.

`/SecLists/Discovery/DNS/subdomains-top1million-5000.txt` is a wordlist allowing sub-domain fuzzing.

```shell
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/
```

## Vhost Fuzzing : 

```shell
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'
```
## Filtering Results : 

```shell
NolanCarougeHTB@htb[/htb]$ ffuf -h
...SNIP...
MATCHER OPTIONS:
  -mc              Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403)
  -ml              Match amount of lines in response
  -mr              Match regexp
  -ms              Match HTTP response size
  -mw              Match amount of words in response

FILTER OPTIONS:
  -fc              Filter HTTP status codes from response. Comma separated list of codes and ranges
  -fl              Filter by amount of lines in response. Comma separated list of line counts and ranges
  -fr              Filter regexp
  -fs              Filter HTTP response size. Comma separated list of sizes and ranges
  -fw              Filter by amount of words in response. Comma separated list of word counts and ranges
<...SNIP...>
```

```shell
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://83.136.249.57:50425/ -H 'Host: FUZZ.academy.htb' -fs 986
```

## Parameter Fuzzing - GET : 

`/SecLists/Discovery/Web-Content/burp-parameter-names.txt`

```shell
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx
```

## Parameter Fuzzing - POST : 

```shell
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```

## Value Fuzzing : 

Custom wordlist for id :
```bash
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

```shell
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```

```shell
curl http://admin.academy.htb:37714/admin/admin.php -X POST -d 'id=74' -H 'Content-Type: application/x-www-form-urlencoded'
```