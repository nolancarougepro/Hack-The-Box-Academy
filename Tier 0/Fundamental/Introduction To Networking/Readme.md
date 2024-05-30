## Networking Overview : 

![[net_overview.png]]

## Network Types : 

![[Network Types 1.png]]![[Network Types 2.png]]

## Networking Topologies : 

![[Connections.png]]![[Nodes.png]]
![[PointToPoint.png]]![[Bus.png]]
![[Star.png]]![[Ring.png]]![[Mesh.png]]![[Tree.png]]![[Hybrid.png]]![[DaisyChain.png]]

## Proxies : 

A proxy is when a device or service sits in the middle of a connection and acts as a mediator. It is therefore capable of inspecting traffic content.

Several types of proxy :
- `Dedicated Proxy` / `Forward Proxy` : 
![[ForwardProxy.png]]

- `Reverse Proxy` : 
![[ReverseProxy.png]]

- `Transparent Proxy` : 
With a `transparent proxy`, the client doesn't know about its existence.

## Networking Models : 

![[OSI.png]]![[Packet Transfer.png]]

## The OSI Model : 

![[OSIModel.png]]

## The TCP/IP Model : 

![[TCPIP.png]]

The most important tasks of TCP/IP are :

![[RolesTCP.png]]

## Network Layer : 

(Layer 3 of the OSI model). It is broadly responsible for the following functions: 
- `Logical Addressing`
- `Routing`
The most used protocols of this layer are: 
- `IPv4` / `IPv6`
- `IPsec`
- `ICMP`
- `IGMP`
- `RIP`
- `OSPF`

## IP Addresses : 

Each machine has a MAC address, they allow communication on a local network. To communicate via the internet you must use IPv4, IPv6.
- `IPv4` / `IPv6` - describes the unique postal address and district of the receiver's building.
- `MAC` - describes the exact floor and apartment of the receiver.

## IPv4 : 

An IPv4 address is made up of 32 bits (4 bytes ranging from 0 to 255).
It is possible to have 4,294,967,296 unique addresses.

![[Ipv4.png]]
2 reserved addresses. The one for the network address and the other for the broadcast.

## Subnetting : 

![[Networtk Part.png]]
![[Host Part.png]]
![[Network Adress.png]]![[Broadcast Adress.png]]![[Hosts.png]]

## MAC Addresses : 

A MAC address is 48 bits (6 bytes represented in Hexadecimal).
MAC address :
- `DE:AD:BE:EF:13:37`
- `DE-AD-BE-EF-13-37`
- `DEAD.BEEF.1337`

The first half (`3 bytes` / `24 bit`) is the so-called `Organization Unique Identifier` (`OUI`) defined by the `Institute of Electrical and Electronics Engineers` (`IEEE`) for the respective manufacturers. 
The last half of the MAC address is called the `Individual Address Part` or `Network Interface Controller` (`NIC`), which the manufacturers assign. The manufacturer sets this bit sequence only once and thus ensures that the complete address is unique.

![[Local Range Mac.png]]
The last bit identifies the MAC address as `Unicast` (`0`) or `Multicast` (`1`). With `unicast`, it means that the packet sent will reach only one specific host.

![[MAC Unicast.png]]![[MacMulti Broad.png]]
![[Global Locally.png]]

- `MAC spoofing`: This involves altering the MAC address of a device to match that of another device, typically to gain unauthorized access to a network.

- `MAC flooding`: This involves sending many packets with different MAC addresses to a network switch, causing it to reach its MAC address table capacity and effectively preventing it from functioning correctly.

- `MAC address filtering`: Some networks may be configured only to allow access to devices with specific MAC addresses that we could potentially exploit by attempting to gain access to the network using a spoofed MAC address.

ARP protocol to discover MAC addresses when you want to communicate (broadcast request).

## IPv6 Addresses : 

Successor to IPv4. An IPv6 is 128 bits long. The prefix identifies the host and the network part. IPv6 addresses will completely replace IPv4 addresses. They have new features :
- Larger address space
- Address self-configuration (SLAAC)
- Multiple IPv6 addresses per interface
- Faster routing
- End-to-end encryption (IPsec)
- Data packages up to 4 GByte

![[IPv6.png]]
![[TypesIPv6.png]]![[FormatIPv6.png]]

## Networking Key Terminology : 

![[Protocols1.png]]
![[Protocols4.png]]![[Protocols5.png]]![[Protocols3.png]]
![[Protocols2.png]]

## Common Protocols : 
### Transmission Control Protocol :

With connection. TCP is therefore more reliable but slower than UDP.

![[ThreeWayHandshake.png]]

![[TCPProt1.png]]
![[TCPProt3.png]]
![[TCPProt2.png]]
![[TCPProt4.png]]

### User Datagram Protocol : 

Without connection. No verification that the message is received. UDP is therefore faster than TCP but less reliable.

![[UDP1.png]]
![[UDP2.png]]

### ICMP : 

ICMP is a protocol used by devices to communicate with each other over the Internet for several reasons including error reporting and status information. For example the **ping** request. The most used version of ICMP is ICMPv4 (there is ICMPv6 for IPv6 addresses only). There is a TTL field in the packet header which limits the lifetime of the packet (to prevent the packet from going around in circles).

![[ICMP Request.png]]
![[ICMP Message.png]]

### VoIP : 

Method used to transmit voice. Used in particular for Skype, WhatsApp, Google Hangouts, Zoom... The ports used by VoIP for session initialization (SIP) are often TCP port 5060 and TCP 5061. TCP port 1720 can also be used.

The most used SIP methods and requests:

![[Sip method.png]]

## Wireless Networks :

The data is transported by radio waves (RF: 2.4 or 5 GHz for WiFi). Each device has an adapter to convert the data into RF signals and send them into the air.
The [IEEE 802.11](https://en.wikipedia.org/wiki/IEEE_802.11) protocol defines the technical details of how wireless devices should communicate. 

The different fields of the Connection request frame:

![[RequestFrame.png]]![[Etablissement Connection.png]]

Main security in WiFi: 
- Encryption
- Access Control
- Firewall

WEP: 40 or 104 bit key for encrypting data. (Bruteforce possibility)
WPA: Uses AES with a 128-bit key.

## Virtual Private Networks : 

VPN typically uses the ports `TCP/1723` for [Point-to-Point Tunneling Protocol](https://www.lifewire.com/pptp-point-to-point-tunneling-protocol-818182) `PPTP` VPN connections and `UDP/500` for [IKEv1](https://www.cisco.com/c/en/us/support/docs/security-vpn/ipsec-negotiation-ike-protocols/217432-understand-ipsec-ikev1-protocol.html) and [IKEv2](https://nordvpn.com/blog/ikev2ipsec/) VPN connections.

![[VPN.png]]

### IPsec : 

Protocol that encrypts and authenticates internet communications.
1. [Authentication Header](https://www.ibm.com/docs/en/i/7.1?topic=protocols-authentication-header) (`AH`): This protocol provides integrity and authenticity for IP packets but does not provide encryption. It adds an authentication header to each IP packet, which contains a cryptographic checksum that can be used to verify that the packet has not been tampered with.
    
2. [Encapsulating Security Payload](https://www.ibm.com/docs/en/i/7.4?topic=protocols-encapsulating-security-payload) (`ESP`): This protocol provides encryption and optional authentication for IP packets. It encrypts the data payload of each IP packet and optionally adds an authentication header, similar to AH.

2 operating modes:

![[IPSec.png]]![[Exemple IPSEc.png]]

## Vendor Specific Information : 

Cisco IOS for routers and switches (Cisco brand). It offers several features:
- Support for IPv6
- Quality of Service (QoS)
- Security features such as encryption and authentication
- Virtualization features such as Virtual Private LAN Service (VPLS)
- Virtual Routing and Forwarding (VRF)
Either from the command line (CLI) or with a graphical interface (GUI). It supports several network protocols including :
![[Ciscoios.png]]

Cisco passwords :
![[Motsdepasse Cisco.png]]

### VLANs : 

Network group connected to a switch.

![[VLAN.png]]

The benefits include :
- `Better Organization`: Network administrators can group endpoints based on any common attribute they share.
- `Increased Security`: Network segmentation disallows unauthorized members from sniffing network packets in other `VLANs`.
- `Simplified Administration`: Network administrators do not have to worry about the physical locations of an endpoint.
- `Increased Performance`: With reduced broadcast traffic for all endpoints, more bandwidth is made available for use by the network.

## Key Exchange Mechanisms :

![[AlgoChiffre.png]]

## Authentication Protocols :

![[AuthProt1.png]]![[AuthProt2.png]]

## TCP/UDP Connections : 

Header d'un paquet IP : 

![[IP header.png]]

## Cryptography : 

Symmetrique : AES, DES.
Asymétrique (clé privé et publique) : RSA, PGP, ECC

Cipher Mode : 

![[Cipher Mode.png]]