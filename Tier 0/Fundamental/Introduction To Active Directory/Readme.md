## Active Directory Structure : 

A basic AD user account with no added privileges can be used to enumerate the majority of objects contained within AD, including but not limited to:

![[Domain.png]]
![[TreeAD.png]]![[AD.png]]
![[ADForestandDomain.png]]

## Active Directory Terminology : 
#### Object : 

An AD resource (OU, Printers, Users..).

#### Attributes : 

Used to define a characteristic of an object (displayName, Full Name, ..).

#### Schema : 

It defines the types of objects that can exist in the AD as well as their associated attributes.

#### Domain : 

Group of objects (Computers, Users, OUs, Groups..).

#### Forest : 

A collection of domains. Each forest is independent but can have trust relationships with others.

#### Tree : 

A collection of domains that start from a single root domain.
Let's say we have two trees in an AD forest: `inlanefreight.local` and `ilfreight.local`. A child domain of the first would be `corp.inlanefreight.local` while a child domain of the second could be `corp.ilfreight.local`.

#### Container : 

Contains another item. The container has a well-defined place in the hierarchy.

#### Leaf : 

Does not contain any other objects. Can be found at the end of the subtree hierarchy.

#### Global Unique Identifier (GUID) : 

A [GUID](https://docs.microsoft.com/en-us/windows/win32/adschema/a-objectguid) is a unique 128-bit value assigned when a domain user or group is created. Every single object created by Active Directory is assigned a GUID, not only user and group objects.


![[dn_rdn2.webp]]

## Active Directory Objects : 

![[adobjects.webp]]

## Active Directory Functionality :

![[RolesMaster.png]]![[TrustType.png]]![[trusts-diagram.webp]]

## Kerberos, DNS, LDAP, MSRPC : 

### Kerberos (Port 88 both TCP and UDP): 

![[Kerb_auth.webp]]

### DNS : 

![[dns_highlevel.webp]]

Command to find the DNS name or get the IP address of a server :
```powershell-session
nslookup 172.16.6.5
```

### LDAP : 

![[LDAP_auth.webp]]

Comparison between AD and LDAP / Apache and HTTP.
2 Types of authentication:

- Simple Authentication :
This includes anonymous authentication, unauthenticated authentication, and username/password authentication. Simple authentication means that a `username` and `password` create a BIND request to authenticate to the LDAP server.

- SASL Authentication : 
[The Simple Authentication and Security Layer (SASL)](https://en.wikipedia.org/wiki/Simple_Authentication_and_Security_Layer) framework uses other authentication services, such as Kerberos, to bind to the LDAP server and then uses this authentication service (Kerberos in this example) to authenticate to LDAP.

### MSRPC : 

![[MSRCP.png]]

## NTLM Authentication : 

![[HashProtocol.png]]![[ntlm_auth.webp]]
![[NTLM Auth.png]]

```shell-session
NolanCarougeHTB@htb[/htb]$ crackmapexec smb 10.129.41.19 -u rachel -H e46b9e548fa0d122de7f59fb6d48eaa2

SMB         10.129.43.9     445    DC01      [*] Windows 10.0 Build 17763 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.43.9     445    DC01      [+] INLANEFREIGHT.LOCAL\rachel:e46b9e548fa0d122de7f59fb6d48eaa2 (Pwn3d!)
```

## Active Directory Rights and Privileges : 

![[GroupName1.png]]![[GroupName2.png]]![[GroupName3.png]]![[Privilege.png]]

List user privileges :
```powershell-session
whoami /priv
```

## Security in Active Directory :

![[CIA-triad-diag.webp]]

## Examining Group Policy : 
![[HTB Academy/Tier 0/Fundamental/INTRODUCTION TO ACTIVE DIRECTORY/Images/Policy.png]]![[gpo_levels.webp]]