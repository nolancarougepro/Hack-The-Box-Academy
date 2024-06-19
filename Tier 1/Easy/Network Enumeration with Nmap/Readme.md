## Enumeration : 

`Enumeration` is the most critical part of all. The art, the difficulty, and the goal are not to gain access to our target computer. Instead, it is identifying all of the ways we could attack a target we must find.

It's not hard to get access to the target system once we know how to do it. Most of the ways we can get access we can narrow down to the following two points :

- `Functions and/or resources that allow us to interact with the target and/or provide additional information.`
    
- `Information that provides us with even more important information to access our target.`

`Enumeration is the key`.

## Introduction to Nmap : 

Network Mapper (`Nmap`) is an open-source network analysis and security auditing tool written in C, C++, Python, and Lua. It is designed to scan networks and identify which hosts are available on the network using raw packets, and services and applications, including the name and version, where possible. It can also identify the operating systems and versions of these hosts.

The tool is one of the most used tools by network administrators and IT security specialists. It is used to :

- Audit the security aspects of networks
- Simulate penetration tests
- Check firewall and IDS settings and configurations
- Types of possible connections
- Network mapping
- Response analysis
- Identify open ports
- Vulnerability assessment as well.

Nmap offers many different types of scans that can be used to obtain various results about our targets. Basically, Nmap can be divided into the following scanning techniques :

- Host discovery
- Port scanning
- Service enumeration and detection
- OS detection
- Scriptable interaction with the target service (Nmap Scripting Engine)

The syntax for Nmap is fairly simple and looks like this :

```shell
NolanCarougeHTB@htb[/htb]$ nmap <scan types> <options> <target>
```

For example, the TCP-SYN scan (`-sS`) is one of the default settings unless we have defined otherwise and is also one of the most popular scan methods. The TCP-SYN scan sends one packet with the SYN flag and, therefore, never completes the three-way handshake, which results in not establishing a full TCP connection to the scanned port.

- If our target sends an `SYN-ACK` flagged packet back to the scanned port, Nmap detects that the port is `open`.
- If the packet receives an `RST` flag, it is an indicator that the port is `closed`.
- If Nmap does not receive a packet back, it will display it as `filtered`. Depending on the firewall configuration, certain packets may be dropped or ignored by the firewall.

## Host Discovery : 

There are many options `Nmap` provides to determine whether our target is alive or not. The most effective host discovery method is to use **ICMP echo requests**. 

It is always recommended to store every single scan. This can later be used for comparison, documentation, and reporting.

Scan Network Range : 

```shell
NolanCarougeHTB@htb[/htb]$ sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
```

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%201/Easy/Network%20Enumeration%20with%20Nmap/Images/scan_opt.png)

This scanning method works only if the firewalls of the hosts allow it.

`Nmap` also gives us the option of working with lists and reading the hosts from this list instead of manually defining or typing them in.

```shell
NolanCarougeHTB@htb[/htb]$ cat hosts.lst

10.129.2.4
10.129.2.10
10.129.2.11
10.129.2.18
10.129.2.19
10.129.2.20
10.129.2.28
```

```shell
NolanCarougeHTB@htb[/htb]$ sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
```

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%201/Easy/Network%20Enumeration%20with%20Nmap/Images/scan_opt_2.png)

It can also happen that we only need to scan a small part of a network. An alternative to the method we used last time is to specify multiple IP addresses.

```shell
NolanCarougeHTB@htb[/htb]$ sudo nmap -sn -oA tnet 10.129.2.18 10.129.2.19 10.129.2.20| grep for | cut -d" " -f5

NolanCarougeHTB@htb[/htb]$ sudo nmap -sn -oA tnet 10.129.2.18-20| grep for | cut -d" " -f5
```

Before we scan a single host for open ports and its services, we first have to determine if it is alive or not. For this, we can use the same method as before.

```shell
NolanCarougeHTB@htb[/htb]$ sudo nmap 10.129.2.18 -sn -oA host 
```

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%201/Easy/Network%20Enumeration%20with%20Nmap/Images/scan_opt_3.png)

If we disable port scan (`-sn`), Nmap automatically ping scan with `ICMP Echo Requests` (`-PE`). Once such a request is sent, we usually expect an `ICMP reply` if the pinging host is alive.

We can confirm this with the "`--packet-trace`" option. To ensure that ICMP echo requests are sent, we also define the option (`-PE`) for this.

```shell
NolanCarougeHTB@htb[/htb]$ sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace 
```

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%201/Easy/Network%20Enumeration%20with%20Nmap/Images/scan_opt_4.png)

Another way to determine why Nmap has our target marked as "alive" is with the "`--reason`" option.

```shell
NolanCarougeHTB@htb[/htb]$ sudo nmap 10.129.2.18 -sn -oA host -PE --reason 
```

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%201/Easy/Network%20Enumeration%20with%20Nmap/Images/scan_opt_5.png)

More strategies about host discovery can be found at : [https://nmap.org/book/host-discovery-strategies.html](https://nmap.org/book/host-discovery-strategies.html)

## Host and Port Scanning : 

The information we need includes :

- Open ports and its services
- Service versions
- Information that the services provided
- Operating system

There are a total of 6 different states for a scanned port we can obtain :

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%201/Easy/Network%20Enumeration%20with%20Nmap/Images/scanned_port.png)

By default, `Nmap` scans the top 1000 TCP ports with the SYN scan (`-sS`). We can define the ports one by one (`-p 22,25,80,139,445`), by range (`-p 22-445`), by top ports (`--top-ports=10`) from the `Nmap` database that have been signed as most frequent, by scanning all ports (`-p-`) but also by defining a fast port scan, which contains top 100 ports (`-F`).

The Nmap [TCP Connect Scan](https://nmap.org/book/scan-methods-connect-scan.html) (`-sT`) uses the TCP three-way handshake to determine if a specific port on a target host is open or closed. The `Connect` scan is useful because it is the most accurate way to determine the state of a port, and it is also the most stealthy.

When a port is shown as filtered, it can have several reasons. In most cases, firewalls have certain rules set to handle specific connections. The packets can either be `dropped`, or `rejected`. When a packet gets dropped, `Nmap` receives no response from our target, and by default, the retry rate (`--max-retries`) is set to 1. This means `Nmap` will resend the request to the target port to determine if the previous packet was not accidentally mishandled.

To be able to track how our sent packets are handled, we deactivate the ICMP echo requests (`-Pn`), DNS resolution (`-n`), and ARP ping scan (`--disable-arp-ping`) again.

Some system administrators sometimes forget to filter the UDP ports in addition to the TCP ones. Since `UDP` is a `stateless protocol` and does not require a three-way handshake like TCP. We do not receive any acknowledgment. Consequently, the timeout is much longer, making the whole `UDP scan` (`-sU`) much slower than the `TCP scan` (`-sS`).

```shell
NolanCarougeHTB@htb[/htb]$ sudo nmap 10.129.2.28 -F -sU
```

Another disadvantage of this is that we often do not get a response back because `Nmap` sends empty datagrams to the scanned UDP ports, and we do not receive any response. If the UDP port is `open`, we only get a response if the application is configured to do so.

Another handy method for scanning ports is the `-sV` option which is used to get additional available information from the open ports. This method can identify versions, service names, and details about our target.

More information about port scanning techniques we can find at : [https://nmap.org/book/man-port-scanning-techniques.html](https://nmap.org/book/man-port-scanning-techniques.html)

## Saving the Results : 

While we run various scans, we should always save the results. We can use these later to examine the differences between the different scanning methods we have used. `Nmap` can save the results in 3 different formats.

- Normal output (`-oN`) with the `.nmap` file extension
- Grepable output (`-oG`) with the `.gnmap` file extension
- XML output (`-oX`) with the `.xml` file extension

We can also specify the option (`-oA`) to save the results in all formats. The command could look like this :

```shell
NolanCarougeHTB@htb[/htb]$ sudo nmap 10.129.2.28 -p- -oA target
```

With the XML output, we can easily create HTML reports that are easy to read, even for non-technical people. To convert the stored results from XML format to HTML, we can use the tool `xsltproc`.

```shell
NolanCarougeHTB@htb[/htb]$ xsltproc target.xml -o target.html
```

## Service Enumeration : 

A full port scan takes quite a long time. To view the scan status, we can press the `[Space Bar]` during the scan, which will cause `Nmap` to show us the scan status.

```shell
NolanCarougeHTB@htb[/htb]$ sudo nmap 10.129.2.28 -p- -sV
```

Another option (`--stats-every=5s`) that we can use is defining how periods of time the status should be shown.

We can also increase the `verbosity level` (`-v` / `-vv`), which will show us the open ports directly when `Nmap` detects them.

## Nmap Scripting Engine : 

Nmap Scripting Engine (`NSE`) is another handy feature of `Nmap`. It provides us with the possibility to create scripts in Lua for interaction with certain services. There are a total of 14 categories into which these scripts can be divided :

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%201/Easy/Network%20Enumeration%20with%20Nmap/Images/scripts.png)

We have several ways to define the desired scripts in `Nmap`.

Default Scripts : 

```shell
NolanCarougeHTB@htb[/htb]$ sudo nmap <target> -sC
```

Specific Scripts Category : 

```shell
NolanCarougeHTB@htb[/htb]$ sudo nmap <target> --script <category>
```

Defined Scripts : 

```shell
NolanCarougeHTB@htb[/htb]$ sudo nmap <target> --script <script-name>,<script-name>,...
```

`Nmap` also gives us the ability to scan our target with the aggressive option (`-A`). This scans the target with multiple options as service detection (`-sV`), OS detection (`-O`), traceroute (`--traceroute`), and with the default NSE scripts (`-sC`).

More information about NSE scripts and the corresponding categories we can find at : [https://nmap.org/nsedoc/index.html](https://nmap.org/nsedoc/index.html)

## Performance : 

We can use various options to tell `Nmap` how fast (`-T <0-5>`), with which frequency (`--min-parallelism <number>`), which timeouts (`--max-rtt-timeout <time>`) the test packets should have, how many packets should be sent simultaneously (`--min-rate <number>`), and with the number of retries (`--max-retries <number>`) for the scanned ports the targets should be scanned.

Generally, `Nmap` starts with a high timeout (`--min-RTT-timeout`) of 100ms.
Another way to increase the scans' speed is to specify the retry rate of the sent packets (`--max-retries`). The default value for the retry rate is `10`, so if `Nmap` does not receive a response for a port, it will not send any more packets to the port and will be skipped.
The default timing template used when we have defined nothing else is the normal (`-T 3`).

- `-T 0` / `-T paranoid`
- `-T 1` / `-T sneaky`
- `-T 2` / `-T polite`
- `-T 3` / `-T normal`
- `-T 4` / `-T aggressive`
- `-T 5` / `-T insane`

More information about scan performance we can find at [https://nmap.org/book/man-performance.html](https://nmap.org/book/man-performance.html)

## Firewall and IDS/IPS Evasion : 

`Nmap` gives us many different ways to bypass firewalls rules and IDS/IPS. These methods include the fragmentation of packets, the use of decoys, and others.

A firewall is a security measure against unauthorized connection attempts from external networks. Every firewall security system is based on a software component that monitors network traffic between the firewall and incoming data connections and decides how to handle the connection based on the rules that have been set.

Like the firewall, the intrusion detection system (`IDS`) and intrusion prevention system (`IPS`) are also software-based components. `IDS` scans the network for potential attacks, analyzes them, and reports any detected attacks. `IPS` complements `IDS` by taking specific defensive measures if a potential attack should have been detected.

We already know that when a port is shown as filtered, it can have several reasons. In most cases, firewalls have certain rules set to handle specific connections. The packets can either be `dropped`, or `rejected`. The `dropped` packets are ignored, and no response is returned from the host.

This is different for `rejected` packets that are returned with an `RST` flag. These packets contain different types of ICMP error codes or contain nothing at all.

Such errors can be :

- Net Unreachable
- Net Prohibited
- Host Unreachable
- Host Prohibited
- Port Unreachable
- Proto Unreachable

Nmap's TCP ACK scan (`-sA`) method is much harder to filter for firewalls and IDS/IPS systems than regular SYN (`-sS`) or Connect scans (`sT`) because they only send a TCP packet with only the `ACK` flag.

There are cases in which administrators block specific subnets from different regions in principle. This prevents any access to the target network. Another example is when IPS should block us. For this reason, the Decoy scanning method (`-D`) is the right choice. With this method, Nmap generates various random IP addresses inserted into the IP header to disguise the origin of the packet sent. With this method, we can generate random (`RND`) a specific number (for example: `5`) of IP addresses separated by a colon (`:`).

Another scenario would be that only individual subnets would not have access to the server's specific services. So we can also manually specify the source IP address (`-S`) to test if we get better results with this one.

Connect To The Filtered Port : 

```shell
NolanCarougeHTB@htb[/htb]$ ncat -nv --source-port 53 10.129.2.28 50000
```
