## HyperText Transfer Protocol (HTTP) : 

HTTP : Application layer Protocol (Port 80 by default).
HTTPS : Secure version (Port 443 by default).
Format of a URL:
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Web%20Request/Images/url_structure.webp)
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Web%20Request/Images/ComponentUrl.png)

Before making a DNS query, browsers first check the contents of the file: /etc/hosts?
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Web%20Request/Images/HTTP_Flow.webp)
**Curl** is a very powerful tool for making queries, among other things.
This command saves the response from the server to a file.
```shell-session
curl -O inlanefreight.com/index.html
```
## Hypertext Transfer Protocol Secure (HTTPS) : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Web%20Request/Images/HTTPS_Flow.webp)**Curl** allows you to manage certificates, if it is not valid or dated then the tool will not allow communication.
```shell-session
curl -k https://inlanefreight.com
```
This command will override the certificate verification.
## HTTP Requests and Responses : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Web%20Request/Images/raw_request.webp)
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Web%20Request/Images/raw_response.webp)
```shell-session
curl inlanefreight.com -v
```
This command displays the entire HTTP request. (-vvv allows you to have even more detail).

## HTTP Headers : 

[General headers](https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html) are used in both HTTP requests and responses. They are contextual and are used to `describe the message rather than its contents`.

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Web%20Request/Images/GeneralHeader.png)

Similar to general headers, [Entity Headers](https://www.w3.org/Protocols/rfc2616/rfc2616-sec7.html) can be `common to both the request and response`. These headers are used to `describe the content` (entity) transferred by a message. They are usually found in responses and POST or PUT requests.

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Web%20Request/Images/EntityHeader.png)

The client sends [Request Headers](https://tools.ietf.org/html/rfc2616) in an HTTP transaction. These headers are `used in an HTTP request and do not relate to the content` of the message. The following headers are commonly seen in HTTP requests.

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Web%20Request/Images/RequestHeader.png)

[Response Headers](https://tools.ietf.org/html/rfc7231#section-6) can be `used in an HTTP response and do not relate to the content`. Certain response headers such as `Age`, `Location`, and `Server` are used to provide more context about the response. The following headers are commonly seen in HTTP responses.

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Web%20Request/Images/ResponseHeader.png)

Finally, we have [Security Headers](https://owasp.org/www-project-secure-headers/). With the increase in the variety of browsers and web-based attacks, defining certain headers that enhanced security was necessary. HTTP Security headers are `a class of response headers used to specify certain rules and policies` to be followed by the browser while accessing the website.

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Web%20Request/Images/SecurityHeader.png)

## HTTP Methods and Codes : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Web%20Request/Images/RequestMethods.png)
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Web%20Request/Images/ResponseCodes.png)
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Web%20Request/Images/UsualCodes.png)
