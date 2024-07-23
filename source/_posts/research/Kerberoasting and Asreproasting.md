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
