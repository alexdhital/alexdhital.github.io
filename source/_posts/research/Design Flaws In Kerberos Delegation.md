---
cover: https://i.postimg.cc/fW9FQ5D7/Designer.jpg
title: "A Deep Dive into Kerberos - Part 2: Exploiting Design Flaws in Delegation Mechanisms"
date: 8/25/2024 3:32:40 +06:00
categories: research
tags: [Unconstrained Delegation, Constrained Delegation, Alternate Service Name, S4U2Self, RBCD]
toc: true
toc_number: false
---

# Overview
![Unconstrained Delegation](https://i.postimg.cc/h4XfzHtT/Unconstrained-drawio.png)

When a user wants to access a service eg: **HTTP** the client will ask for **Service Ticket** for HTTP service from the Ticket Granting Server by providing their TGT and SPN `HTTP\dev.dhitalcorp.local`, the Ticket Granting Server will verify the TGT provide them **ST** for that service, the client will then present the ST to the web server which will grant or deny them access. But in a dynamic web application the web application will have to  only display the information and functionalities this user is supposed to access as opposed to an administrator user right? Due to this issue Microsoft introduced unconstrained delegation. When the user sends **ST** to the web server computer, the web server computer will extract the user's **TGT** from the Service Ticket and cache it in its memory then it will send the user's TGT to the domain controller on behalf of this user to request service ticket for database server. After receiving the **ST** for database server it will connect to the database server on behalf of this user and complete the user impersonation to display only the information and functionalities which the client has access to or perform action on the web application as that user. 

**Note:** If unconstrained delegation is setup on a machine it will impersonate the user and delegate that user's credential to any service without any limitation.

# Problem with this Architecture
The main problem with unconstrained delegation is that any user who accesses the web application, the web server computer will cache their TGT in its memory. So if we have administrator access on web server computer we can extract TGT of every user who accessed the web application. Another interesting aspect to unconstrained delegation is that it will cache the user’s TGT regardless of which service is being accessed by the user from that computer. So, if an admin or user accesses a file share or any other service from that machine, their TGT will be cached.

# Exploiting Unconstrained Delegation
First we need to identify computers setup for Unconstrained Delegation on the domain. We can use PowerView or Rubeus.
```
PS C:\Users\Alex> Get-DomainComputer -UnConstrained
```
