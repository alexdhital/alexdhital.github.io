---
cover: https://i.ibb.co/8sSpR83/CRTP.png
title: CRTP Short Review
date: 09/18/2023 09:45:47 +07:00
categories: certification-review
tags: [CRTP, Active Directory, altered security]
---

## Overview
After my OSCP I felt I needed a good grasp and overall in depth understanding on Active Directory so I decided to purchase the `Attacking and Defending Active Directory` course from altered security which provides `Certified Red Team Professional` certificate after succesfully tackling the `24 hour` exam. I took the 30 days lab access for `$249`. The course ships with hours of video content, diagrams, walkthrough videos and a lab wiki. Instead of putting students in a large network and letting them to figure our everything `Altered Security` does a great job in providing walkthrough explaining each and every step in detail.

## The Labs and Course
![](https://i.ibb.co/8zyc3BY/Altered-Security.png)
The Lab instance can be accessed via vpn or via guacamole on browser. I personally used vpn connection to access the lab. It is an `assumed breach` scenario where we are given low privilege access on a workstation. This workstation includes pretty much every tool like modified version of mimikat, powerview,nrubeus, bloodhound, covenant, heidi sql, PowerUpSQL, etc needed for compromising the entire lab environment. Nikhil does an awesome job of taking a student from basic of Active Directory and reconnaissance of Domain, Forest, Users, Groups, OU, Trust, ACLs, hunting for users with high privilege, lateral movement across hosts, `credential dumping` to attacks like `Kerberoasting`, `Asreproasting`, pre-existing architecture problems in `Kerberos` and how to attack them including attacks like `Unconstrained delegation`, `Constrained Delegation`, `Resource Based Constrained Delegation`, etc. The course also covers attacking `Active Directory Certificate Services` which I found quite interesting and relatively a much needed topic for me to explore. The student are not only given the tools and commands but explained in detail how a tool or particular command works. One of the most overlooked topic `persistance` which is much needed during real engagements is covered very well including persistance techniques like `AdminSDHolder`, `DSRM(Directory Services Restore Mode)` and `Persistance using ACLs`. One of my favourite and fun topic in the overall course was `Attacking MSSQL` servers and abusing `database links` to compromise sql servers in another domain or even across forest.  

## The Exam
The exam can be started anytime from the student dashboard and after couple of confirmation the exam environment gets created and we can start our exam. The exam is `24 hours` and not protocored. We are given 5 target machines which are spread across different domains or forest. The goal of the exam to obtain `OS Command Execution` on all 5 of them excluding the initial workstation where we are given low privilege access. One thing to remember is that we will not be given any tools on the initial workstation and all the required tools need to be manually transferred. There will be a folder specifically excluded from `Windows Defender` where we can transfer our tools so they won't get flagged by `Defender`. Remember all the machines will have defender enabled so it is our job to `disable` or `bypass` windows defender using various techniques taught in the course. I started my exam at `8 AM` nepali time and had achieved `OS Command execution` on all 5 machines before `3 PM`. If you have followed the course content, watched every video and took good notes the exam is relatively straightforward. Next day I created a fine report spending 5-6 hours and submitted the report. On `Wednesday August 23, 2023` I received email on my inbox that I had successfully cleared the examination.
![](https://i.ibb.co/Gvh0Gw3/resul.png)

## Conclusion
Completing this course was a fantastic learning experience for me. The hands-on labs, detailed walkthroughs, and comprehensive content truly deepened my understanding of Active Directory security. The exam was very straightforward, and successfully passing it was a rewarding milestone. Overall, the course significantly enhanced my skills in red teaming and Active Directory pentesting. I highly recommend it to anyone looking to specialize in Active Directory security.

![](https://i.ibb.co/VWz4324/cert.png)

## Some Tips
- Be patient do not rush the exam is very straightforward
- Take detailed note of every attack and command
- Do not rely on a single tool
- Prepare a solid methodology and follow accordingly
- Go through the lab at least 2-3 times
