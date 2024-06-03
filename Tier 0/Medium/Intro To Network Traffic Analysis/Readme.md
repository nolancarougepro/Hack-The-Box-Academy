## Network Traffic Analysis :

`Network Traffic Analysis (NTA)` can be described as the act of examining network traffic to characterize common ports and protocols utilized.

![[use_cases.png]]
![[tools.png]]

## Networking Primer - Layers 1-4 :

Quick refresher on networking (cf [Introduction to Networking](https://academy.hackthebox.com/course/preview/introduction-to-networking)).

![[net_models_pdu2.webp]]
![[pdu-wireshark.webp]]

### MAC-Addressing :

Each logical or physical interface attached to a host has a Media Access Control (`MAC`) address. This address is a 48-bit `six octet` address represented in hexadecimal format. 
MAC-addressing is utilized in Layer two ( `the data-link or link-layer depending on which model you look at` ) communications between hosts. This works through host-to-host communication within a broadcast domain.

### IP Addressing :

The Internet Protocol (`IP`) was developed to deliver data from one host to another across network boundaries. By nature, IP is a connectionless protocol that provides no assurances that data will reach its intended recipient.

#### IPv4 :

An IPv4 address is made up of a 32-bit `four octet` number represented in decimal format. Each octet of an IP address can be represented by a number ranging from `0` to `255`. When examining a PDU, we will find IP addresses in layer three (`Network`) of the OSI model and layer two (`internet`) of the TCP-IP model. 

#### IPv6 : 

IPv6 provides us a much larger address space that can be utilized for any networked purpose. IPv6 is a 128-bit address `16 octets` represented in Hexadecimal format. 
Along with a much larger address space, IPv6 provides: Better support for Multicasting (sending traffic from one to many) Global addressing per device Security within the protocol in the form of IPSec Simplified Packet headers allow for easier processing and move from connection to connection without being re-assigned an address.

IPv6 Addressing Types :
![[addressing_type.png]]

TCP vs UDP :
![[TCPUDP.png]]

One of the ways TCP ensures the delivery of data from server to client is the utilization of sessions. These sessions are established through what is called a three-way handshake. To make this happen, TCP utilizes an option in the TCP header called flags : SYN, SYN/ACK, ACK. 
Before session termination, we should see a packet pattern of : FIN/ACK, FIN/ACK, ACK.

## Networking Primer - Layers 5-7 :

### HTTP : 

Hypertext Transfer Protocol (`HTTP`) is a stateless Application Layer protocol that has been in use since 1990. HTTP enables the transfer of data in clear text between a client and server over TCP. HTTP utilizes ports 80 or 8000 over TCP during normal operations.

#### HTTP Methods : 

![[methods.png]]

### HTTPS : 

HTTP Secure (`HTTPS`) is a modification of the HTTP protocol designed to utilize Transport Layer Security (`TLS`) or Secure Sockets Layer (`SSL`) with older applications for data security. TLS is utilized as an encryption mechanism to secure the communications between a client and a server.
Before the TLS mechanism was in place, we were vulnerable to Man-in-the-middle attacks and other types of reconnaissance or hijacking, meaning anyone in the same LAN as the client or server could view the web traffic if they were listening on the wire.

Even though it is HTTP at its base, HTTPS utilizes ports 443 and 8443 instead of the standard port 80.

1. Client and server exchange hello messages to agree on connection parameters.
2. Client and server exchange necessary cryptographic parameters to establish a premaster secret.
3. Client and server will exchange x.509 certificates and cryptographic information allowing for authentication within the session.
4. Generate a master secret from the premaster secret and exchanged random values.
5. Client and server issue negotiated security parameters to the record layer portion of the TLS protocol.
6. Client and server verify that their peer has calculated the same security parameters and that the handshake occurred without tampering by an attacker.
### FTP : 

File Transfer Protocol (`FTP`) is an Application Layer protocol that enables quick data transfer between computing devices. FTP can be utilized from the command-line, web browser, or through a graphical FTP client such as FileZilla. FTP itself is established as an insecure protocol, and most users have moved to utilize tools such as SFTP to transfer files through secure channels.

FTP uses ports 20 and 21 over TCP. Port 20 is used for data transfer, while port 21 is utilized for issuing commands controlling the FTP session.

FTP is capable of running in two different modes, `active` or `passive`. Active is the default operational method utilized by FTP, meaning that the server listens for a control command `PORT` from the client, stating what port to use for data transfer. Passive mode enables us to access FTP servers located behind firewalls or a NAT-enabled link that makes direct TCP connections impossible.

FTP Commands : 
![[FTPcommand.png]]

For more information on FTP, see `RFC:959`.

### SMB : 

Server Message Block (`SMB`) is a protocol most widely seen in Windows enterprise environments that enables sharing resources between hosts over common networking architectures. SMB is a connection-oriented protocol that requires user authentication from the host to the resource to ensure the user has correct permissions to use that resource or perform actions. In the past, SMB utilized NetBIOS as its transport mechanism over UDP ports 137 and 138. Since modern changes, SMB now supports direct TCP transport over port 445, NetBIOS over TCP port 139, and even the QUIC protocol.

## The Analysis Process : 

Traffic Analysis is a `detailed examination of an event or process`, determining its origin and impact, which can be used to trigger specific precautions and/or actions to support or prevent future occurrences.

Traffic capturing and analysis can be performed in two different ways, `active` or `passive`. Each has its dependencies. With passive, we are just copying data that we can see without directly interacting with the packets. For active traffic capture and analysis, the needs are a bit different. It  can also be referred to as `in-line` traffic captures. With both, how we analyze the data is up to us.

![[traffic_capture_dependencies.png]]

## Tcpdump Fundamentals : 

`Tcpdump` is a command-line packet sniffer that can directly capture and interpret data frames from a file or network interface.

![[tcp_dump_switch.png]]

## Tcpdump Packet Filtering : 

![[Tcpdump_filter.png]]

## Analysis with Wireshark : 

`Wireshark` is a free and open-source network traffic analyzer much like tcpdump but with a graphical interface.

TShark is a purpose-built terminal tool based on Wireshark. TShark shares many of the same features that are included in Wireshark and even shares syntax and options. TShark is perfect for use on machines with little or no desktop environment and can easily pass the capture information it receives to another tool via the command line.

![[thark_swiches.png]]

