## Tool Development : 

The development of tools has many advantages. Besides the fact that we practice and learn specific programming languages during the development process, we also understand how such programs are developed and how the communication between server and client works. This gives us a better understanding of the structures of programs and some repertoire, which will help us understand the processes faster and easier.

Before we start to develop our tool, we need the information we want to work with. Therefore it is essential to understand every step of the interaction with the server to track and reproduce it. To get or query this information, we need to understand how the communication between the services, in this case, DNS, works, and how it is structured.

## DNS Structure : 

DNS is also known as the "phone book of the Internet." Like searching a phone book for a name to get the phone number, DNS looks for a computer name (domain name) to get its IP address. DNS is generally used to resolve computer names into IP addresses and reversed them. The components of a DNS service consist of :

- `Name servers`
- `Zones`
- `Domain names`
- `IP addresses`

The name servers contain so-called `zones` or `zone files`. In simple terms, zone files are lists of entries for the corresponding domain. These zone files contain `IP addresses` to the specific `domains` and `hosts`. We can find them on the Pwnbox under "`/etc/hosts`."

Let us take the following fully qualified domain name (`FQDN`) as an example :

- `www.domain-A.com`

A domain is used to give real names to computer's IP addresses and, at the same time, to divide them into a hierarchical structure. 

```shell
.
├── com.
│   ├── domain-A.
│   │   ├── blog.
│   │   ├── ns1.
│   │   └── www.
│   │ 
│   ├── domain-B.
│   │   └── ...
│   └── domain-C.
│       └── ...
│
└── net.
│   ├── domain-D.
│   │   └── ...
│   ├── domain-E.
│   │   └── ...
│   └── domain-F.
│       └── ...
└── ...
│   ├── ...
│   └── ...
```

![[tooldev-dns.webp]]

Each domain consists of at least two parts:

1. `Top-Level Domain` (`TLD`)
2. `Domain Name`

From the last example, the domain name would be "`inlanefreight`" and the TLD then "`com`". The DNS servers are divided into four different types :

- `Recursive resolvers` (`DNS Recursor`)
- `Root name server`
- `TLD name server`
- `Authoritative name servers`

The recursive resolver acts as an agent between the client and the name server. After the recursive resolver receives a DNS query from a web client, it responds to this query with cached data, or it sends a query to a root name server, followed by a query to a TLD name server and finally a final query to an authoritative name server. Once it has received a response from the authoritative name server with the requested IP address, the recursive resolver sends the client's response.

Thirteen root name servers can be reached under IPv4 and IPv6 addresses. An international non-profit organization maintains these root name servers called the Internet Corporation for Assigned Names and Numbers (`ICANN`). Every recursive resolver knows these 13 root name servers. We find the 13 root name servers on the domain `root-servers.net` with the corresponding letter as a subdomain.

```shell
NolanCarougeHTB@htb[/htb]$ dig ns root-servers.net | grep NS | sort -u                                                                          

; EDNS: version: 0, flags:; udp: 4096
;; ANSWER SECTION:
;; flags: qr rd ra; QUERY: 1, ANSWER: 13, AUTHORITY: 0, ADDITIONAL: 1
;root-servers.net.		IN	NS
root-servers.net.	6882	IN	NS	a.root-servers.net.
root-servers.net.	6882	IN	NS	b.root-servers.net.
root-servers.net.	6882	IN	NS	c.root-servers.net.
root-servers.net.	6882	IN	NS	d.root-servers.net.
root-servers.net.	6882	IN	NS	e.root-servers.net.
root-servers.net.	6882	IN	NS	f.root-servers.net.
root-servers.net.	6882	IN	NS	g.root-servers.net.
root-servers.net.	6882	IN	NS	h.root-servers.net.
root-servers.net.	6882	IN	NS	i.root-servers.net.
root-servers.net.	6882	IN	NS	j.root-servers.net.
root-servers.net.	6882	IN	NS	k.root-servers.net.
root-servers.net.	6882	IN	NS	l.root-servers.net.
root-servers.net.	6882	IN	NS	m.root-servers.net.
```

These 13 root name servers represent the 13 different types of root name servers. It does not mean that it only spread over 13 hosts, but over 600 copies of these root name servers worldwide.

A TLD name server manages the information on all domain names that have the same TLD. These TLD name servers are the responsibility of the Internet Assigned Numbers Authority (`IANA`) and are managed by it. This means that all domains under the TLD "`.com`" are managed by the corresponding TLD name server.

Authoritative name servers store DNS record information for domains. These servers are responsible for providing answers to requests from name servers with the IP address and other DNS entries for a web page so the web page can be addressed and accessed by the client. The authoritative name server is the last step to get an IP address.

## DNS Zones : 

The primary DNS server is the server of the zone file, which contains all authoritative information for a domain and is responsible for administering this zone. The DNS records of a zone can only be edited on the primary DNS server, which then updates the secondary DNS servers.

Secondary DNS servers contain read-only copies of the zone file from the primary DNS server. These servers compare their data with the primary DNS server at regular intervals and thus serve as a backup server. It is useful because a primary name server's failure means that connections without name resolution are no longer possible.

There are two different types of zone transfers.

- `AXFR` - Asynchronous Full Transfer Zone
- `IXFR` - Incremental Zone Transfer

An `AXFR` is a complete transfer of all entries of the zone file. In contrast to full asynchronous transfer, only the changed and new DNS records of the zone file are transferred for an `IXFR` to the secondary DNS servers.

## DNS Records and Queries : 

DNS works with many different records. DNS records are instructions that are located on authoritative DNS servers and contain information about a domain. These entries are written in the DNS syntax that gives the DNS servers the appropriate instructions. Here are the most common DNS records :

![[records.png]]

There are many tools and resources we can work with to send queries to the DNS servers. For example, we can use tools like:

- `dig`
- `nslookup`

`NS` records stand for `name server`. These records specify which DNS server is the authoritative server for the corresponding domain that contains the actual DNS records. Now that we know our target domain, we still need DNS servers we will interact with. For this, we have to find out which DNS servers are responsible for the domain, and for this, we can use the tool called `dig`. In this example, we use the domain called: `inlanefreight.com`.

```shell
NolanCarougeHTB@htb[/htb]$ dig NS inlanefreight.com

<SNIP>
;; ANSWER SECTION:
inlanefreight.com.	60	IN	NS	ns2.inlanefreight.com.
inlanefreight.com.	60	IN	NS	ns1.inlanefreight.com.

<SNIP>
```

```shell
NolanCarougeHTB@htb[/htb]$ dig SOA inlanefreight.com

<SNIP>
;; ANSWER SECTION:
inlanefreight.com.	879	IN	SOA	ns-161.awsdns-20.com. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400

<SNIP>
```

```shell
NolanCarougeHTB@htb[/htb]$ nslookup -type=SPF inlanefreight.com

Non-authoritative answer:
inlanefreight.com	rdata_99 = "v=spf1 include:_spf.google.com include:mail1.inlanefreight.com include:google.com ~all"
```

```shell
NolanCarougeHTB@htb[/htb]$ nslookup -type=txt _dmarc.inlanefreight.com

Non-authoritative answer:
_dmarc.inlanefreight.com	text = "v=DMARC1; p=reject; rua=mailto:master@inlanefreight.com; ruf=mailto:master@inlanefreight.com; fo=1;"
```

## DNS Security : 

More and more companies recognize the value of the DNS as an active `line of defense`, embedded in an in-depth and comprehensive security concept.

This makes sense because the DNS is part of every network connection. The DNS is uniquely positioned in the network to act as a central control point to decide whether a benign or malicious request is received.

Another feed used for the security of DNS servers is `Domain Name System Security Extensions` (`DNSSEC`), designed to ensure the authenticity and integrity of data transmitted through the Domain Name System by securing resource records with digital certificates. `DNSSEC` ensures that the DNS data has not been manipulated and does not originate from any other source. `Private keys` are used to sign the `Resource Records` digitally. `Resource Records` can be signed several times with different private keys, for example, to replace keys that expire in time.

The DNS server that manages a zone to be secured signs its sent resource records using its only known `private key`. Each zone has its zone keys, each consisting of a `private` and a `public key`. `DNSSEC` specifies a new resource record type with the `RRSIG`. It contains the signature of the respective DNS record, and these used keys have a specific validity period and are provided with a `start` and `end date`.

The public key can be used to verify the signature of the recipients of the data. For the `DNSSEC` security mechanisms, it must be supported by the provider of the DNS information and the requesting client system. The requesting clients verify the signatures using the generally known public key of the DNS zone. If a check is successful, manipulating the response is impossible, and the information comes from the requested source.

## DNS Enumeration : 

As with any service we work with and want to find out information, it is essential to understand how DNS works to create a clear structure with the appropriate information. Since DNS can provide much information about the company's infrastructure, we can divide this information into the following categories :

- `DNS Records`
- `Subdomains`/`Hosts`
- `DNS Security`

There is a variety of techniques that can be used for this. These include:

- OSINT
- Certificate Transparency
- Zone transfer

The OSINT is an information procurement from publicly available and open sources. In the simplest case, we can also use search engines like `Bing`, `Yahoo`, and `Google` with the corresponding [Google Dorks](https://securitytrails.com/blog/google-hacking-techniques) of Google to filter out our results.

Also, we can use public services such as [VirusTotal](https://www.virustotal.com), [DNSdumpster](https://dnsdumpster.com/), [Netcraft](https://searchdns.netcraft.com), and others to read known entries for the corresponding domain.

`Certificate Transparency` (`CT`) logs contain all certificates issued by a participating `Certificate Authority` (`CA`) for a specific domain. Therefore, `SSL/TLS certificates` from web servers include `domain names`, `subdomain names`, and `email addresses`. We can use a tool that outputs all the `CT logs` for our target domain from different sources and filtered is [ctfr.py](https://github.com/UnaPibaGeek/ctfr).

`Zone transfer` in DNS refers to the transfer of zones to other DNS servers. This procedure is called the `Asynchronous Full Transfer Zone` (`AXFR`). Since a DNS failure usually has severe consequences for a company, the `zone files` are almost without exception kept identical on several name servers. In the event of changes, it must be ensured that all servers have the same data stock. `Zone transfer` involves the mere transfer of files or records and the detection of discrepancies in the databases of the servers involved.

```shell
NolanCarougeHTB@htb[/htb]$ dig axfr inlanefreight.com @10.129.2.67
```

## Python Code : 

The following guidelines for clean programming will enable us to distinguish clear code from bad code and convert bad code into good code. This becomes especially important when we work with different code or when we need to adapt or modify it. The following five guidelines alone will help us keep our code simple, structured, and efficient.

![[guideline.png]]

There are guidelines developed especially for Python, known as the `Python Enhancement Proposal` (`PEP8`). [PEP8](https://www.python.org/dev/peps/pep-0008/) is a document that contains `guidelines` and `best practices` for writing Python code and was written in 2001 by Guido van Rossum, Barry Warsaw, and Nick Coghlan.

Writing readable code is crucial because other people who are not familiar with our `coding style` need to read and understand our code. If we have guidelines that we follow and recognize, others will also find our code easier to read.

![[pep8.png]]

## Python Modules : 

A quick search on Google will bring us to the module called "[dnspython](https://dnspython.readthedocs.io/en/latest/)".
 
Our goal is to perform a zone transfer, and accordingly, we need to find the appropriate classes and functions to communicate with the DNS servers.
 
Another extension that we can use to develop such tools with Python 3 is [IPython](https://ipython.org/install.html). It supports auto-completion and shows the different options in the corresponding classes and modules in an interactive Python shell.

We have to find out how to resolve our requests by using specific DNS servers. The easiest way with the necessary class would be "`dns.resolver`". In the [documentation](https://dnspython.readthedocs.io/en/latest/resolver-class.html), we can find the class "`Resolver`" which allows us to specify the DNS servers we want to send our requests to.

To make this possible, we import another module called "`argparse`". Accordingly, we also add this information to our notes.

We now have to find the "NS" records for this domain, and instead of using the `dig` tool, we do it with our Python modules. In this example, we still use the domain called :

- `inlanefreight.com`

The corresponding NS servers we found by using the following code :

```shell
NolanCarougeHTB@htb[/htb]$ python3

>>> import dns.resolver
>>> 
>>> nameservers = dns.resolver.query('inlanefreight.com', 'NS')
>>> for ns in nameservers:
...    	print('NS:', ns)
...
NS: ns1.inlanefreight.com.
NS: ns2.inlanefreight.com.
```

In summary, we have the following information now :

```python
Domain = 'inlanefreight.com'
DNS Servers = ['ns1.inlanefreight.com', 'ns2.inlanefreight.com']
```

Now we can summarize all our information and write the first lines of our code.

```python
#!/usr/bin/env python3

# Dependencies:
# python3-dnspython

# Used Modules:
import dns.zone as dz
import dns.query as dq
import dns.resolver as dr
import argparse

# Initialize Resolver-Class from dns.resolver as "NS"
NS = dr.Resolver()

# Target domain
Domain = 'inlanefreight.com'

# Set the nameservers that will be used
NS.nameservers = ['ns1.inlanefreight.com', 'ns2.inlanefreight.com']

# List of found subdomains
Subdomains = []
```

## AXFR Function :

We can divide the process into the following sections :

1. We now want to create a function that tries to perform a zone transfer using the given domain and DNS servers.
    
2. If the zone transfer was successful, we want the found subdomains to be displayed directly and stored in our list.
    
3. In case an error occurs, we want to be informed about the error.

For the `functions`, we should try to use as few passing arguments as possible. Therefore there should not be more than three arguments, because otherwise there can be a high error-proneness. So in the next example, we use the two arguments `domain` and `nameserver`, which we need for the `zone transfer`.

```python
<SNIP>
# List of found subdomains
Subdomains = []

# Define the AXFR Function
def AXFR(domain, nameserver):

        # Try zone transfer for given domain and namerserver
        try:
				# Perform the zone transfer
                axfr = dz.from_xfr(dq.xfr(nameserver, domain))

                # If zone transfer was successful
                if axfr:
                        print('[*] Successful Zone Transfer from {}'.format(nameserver))

                        # Add found subdomains to global 'Subdomain' list
                        for record in axfr:
                                Subdomains.append('{}.{}'.format(record.to_text(), domain))

        # If zone transfer fails
        except Exception as error:
                print(error)
                pass
```

## Main Function : 

The main function is the part of the code where the main program is running. It is essential to keep it as clear as possible, as we will most likely add more functions to our tool later. In this case, we want our tool to try a zone transfer on every DNS server we have specified. We know that the subdomains found will be added to the global subdomain list in the `AXFR()` function. So if this list is not empty, we want to see all subdomains.

```python
#!/usr/bin/env python3

# Dependencies:
# python3-dnspython

# Used Modules:
import dns.zone as dz
import dns.query as dq
import dns.resolver as dr
import argparse

# Initialize Resolver-Class from dns.resolver as "NS"
NS = dr.Resolver()

# Target domain
Domain = 'inlanefreight.com'

# Set the nameservers that will be used
NS.nameservers = ['ns1.inlanefreight.com', 'ns2.inlanefreight.com']

# List of found subdomains
Subdomains = []

# Define the AXFR Function
def AXFR(domain, nameserver):

        # Try zone transfer for given domain and namerserver
        try:
				# Perform the zone transfer
                axfr = dz.from_xfr(dq.xfr(nameserver, domain))

                # If zone transfer was successful
                if axfr:
                        print('[*] Successful Zone Transfer from {}'.format(nameserver))

                        # Add found subdomains to global 'Subdomain' list
                        for record in axfr:
                                Subdomains.append('{}.{}'.format(record.to_text(), domain))

        # If zone transfer fails
        except Exception as error:
                print(error)
                pass

# Main
if __name__=="__main__":

        # For each nameserver
        for nameserver in NS.nameservers:

                #Try AXFR
                AXFR(Domain, nameserver)

        # Print the results
        if Subdomains is not None:
                print('-------- Found Subdomains:')

                # Print each subdomain
                for subdomain in Subdomains:
                        print('{}'.format(subdomain))

        else:
                print('No subdomains found.')
                exit()   
```

## Argparse :

After determining that our script works properly, we can extend our code step by step and add more features. With the tool "dig," we have already seen that we can already define specific arguments in the terminal and pass them to the program. To avoid changing the code frequently, we can add the same function to our script and use it again when we need to.

To include this function, we can use and import the standard module `argparse`.

```python
<SNIP>
# Main
if __name__ == "__main__":

    # ArgParser - Define usage
    parser = argparse.ArgumentParser(prog="dns-axfr.py", epilog="DNS Zonetransfer Script", usage="dns-axfr.py [options] -d <DOMAIN>", prefix_chars='-', add_help=True)

<SNIP>
```

After initializing the parser, we can define the corresponding parameters, which we will define with our script's respective options. For this, we use the `add_argument()` method of the `ArgumentParser`. This method provides us with some parameters that we can use to define the option.

![[parser.png]]

Next, we define the target `domain` parameters and the `nameservers` on which we want to test the zone transfer.

```python
<SNIP>
# Main
if __name__ == "__main__":

    # ArgParser - Define usage
    parser = argparse.ArgumentParser(prog="dns-axfr.py", epilog="DNS Zonetransfer Script", usage="dns-axfr.py [options] -d <DOMAIN>", prefix_chars='-', add_help=True)
	
	# Positional Arguments
    parser.add_argument('-d', action='store', metavar='Domain', type=str, help='Target Domain.\tExample: inlanefreight.htb', required=True)
    parser.add_argument('-n', action='store', metavar='Nameserver', type=str, help='Nameservers separated by a comma.\tExample: ns1.inlanefreight.htb,ns2.inlanefreight.htb')
    parser.add_argument('-v', action='version', version='DNS-AXFR - v1.0', help='Prints the version of DNS-AXFR.py')

    # Assign given arguments
    args = parser.parse_args()

<SNIP>
```

The complete code would look like this.

```python
#!/usr/bin/env python3

# Dependencies:
# python3-dnspython

# Used Modules:
import dns.zone as dz
import dns.query as dq
import dns.resolver as dr
import argparse

# Initialize Resolver-Class from dns.resolver as "NS"
NS = dr.Resolver()

# List of found subdomains
Subdomains = []

# Define the AXFR Function
def AXFR(domain, nameserver):

    # Try zone transfer for given domain and namerserver
    try:
        # Perform the zone transfer
        axfr = dz.from_xfr(dq.xfr(nameserver, domain))

        # If zone transfer was successful
        if axfr:
            print('[*] Successful Zone Transfer from {}'.format(nameserver))

            # Add found subdomains to global 'Subdomain' list
            for record in axfr:
                Subdomains.append('{}.{}'.format(record.to_text(), domain))

    # If zone transfer fails
    except Exception as error:
        print(error)
        pass

# Main
if __name__ == "__main__":

    # ArgParser - Define usage
    parser = argparse.ArgumentParser(prog="dns-axfr.py", epilog="DNS Zonetransfer Script", usage="dns-axfr.py [options] -d <DOMAIN>", prefix_chars='-', add_help=True)

    # Positional Arguments
    parser.add_argument('-d', action='store', metavar='Domain', type=str, help='Target Domain.\tExample: inlanefreight.htb', required=True)
    parser.add_argument('-n', action='store', metavar='Nameserver', type=str, help='Nameservers separated by a comma.\tExample: ns1.inlanefreight.htb,ns2.inlanefreight.htb')
    parser.add_argument('-v', action='version', version='DNS-AXFR - v1.0', help='Prints the version of DNS-AXFR.py')

    # Assign given arguments
    args = parser.parse_args()

    # Variables
    Domain = args.d
    NS.nameservers = list(args.n.split(","))

    # Check if URL is given
    if not args.d:
        print('[!] You must specify target Domain.\n')
        print(parser.print_help())
        exit()

    if not args.n:
        print('[!] You must specify target nameservers.\n')
        print(parser.print_help())
        exit()

    # For each nameserver
    for nameserver in NS.nameservers:

        # Try AXFR
        AXFR(Domain, nameserver)

    # Print the results
    if Subdomains is not None:
        print('-------- Found Subdomains:')

        # Print each subdomain
        for subdomain in Subdomains:
            print('{}'.format(subdomain))

    else:
        print('No subdomains found.')
        exit()
```