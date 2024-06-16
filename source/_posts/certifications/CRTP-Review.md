---
cover: https://i.ibb.co/8sSpR83/CRTP.png
title: CRTP Short Review
date: 12/09/2023 09:45:47 +07:00
categories: certification-review
tags: [CRTP, Active Directory, altered security]
---

## Overview
After my OSCP I felt I needed a good grasp and overall in depth understanding on Active Directory so I decided to purchase the `Attacking and Defending Active Directory` course from altered security which provides `Certified Red Team Professional` certificate after succesfully tackling the `24 hour` exam. I took the 30 days lab access for `$249`. The course ships with hours of video content, diagrams, walkthrough videos and a lab wiki. Instead of putting students in a large network and letting them to figure our everything `Altered Security` does a great job in providing walkthrough explaining each and every step in detail.

## The Labs and Course
![](https://i.ibb.co/8zyc3BY/Altered-Security.png)
The Lab instance can be accessed via vpn or via guacamole on browser. I personally used vpn connection to access the lab. It is an `assumed breach` scenario where we are given low privilege access on a workstation. This workstation includes pretty much every tool like modified version of `mimikatz`, `powerview`, `rubeus`, `bloodhound`, `covenant`, `heidi sql`, `PowerUpSQL`, etc needed for compromising the entire lab environment. Nikhil does an awesome job of taking a student from basic of Active Directory and reconnaissance of `Domain`, `Forest`, `Users`, `Groups`, `OU`, `Trust`, `ACLs`, `hunting for users with high privilege` to attacks like `Kerberoasting`, `Asreproasting`, pre-existing architecture problems in `Kerberoast` and how to attack them including attacks like `Unconstrained delegation`, `Constrained Delegation`, `Resource Based Constrained Delegation`. In the couse, attacking `Active Directory Certificate Services` is also taught which I found quite interesting and relatively a much needed topic for me to explore. The students are not only given the tools and commands but explained in detail how the tool or particular command works. One of the most overlooked topic `persistance` is covered very well including advanced persistance topics in the AD like `AdminSDHolder`, `DSRM(Directory Services Restore Mode)` and `Persistance using ACLs`. One of my favourite and fun topic in the overall course was `Attacking MSSQL` servers and abusing `database links` to compromise servers in another domain or even across forest. 

## The Exam
The exam can be started anytime from the student dashboard and after couple of confirmation the exam environment gets created and we can start our exam. The exam is `24 hours` and not protocored. We are given 5 target machines which are spread across different domains or forest. The goal of the exam to obtain `OS Command Execution` on all 5 of them excluding the initial workstation where we are given low privilege access. One thing to remember is that we will not be given any tools on the initial workstation and all the required tools need to be manually transferred. There will be a folder specifically excluded from `Windows Defender` where we can transfer our tools so they won't get flagged by `Defender`. Remember all the machines will have defender enabled so it is our job to `disable` or `bypass` windows defender using various techniques taught in the course. I started my exam at `8 AM` nepali time and had achieved `OS Command execution` on all 5 machines before `3 PM`. If you have followed the course content, watched every video and took good notes the exam is relatively straightforward. Next day I created a fine report spending 5-6 hours and submitted the report. On `Wednesday August 23, 2023` I received email on my inbox that I had successfully cleared the examination.
![](https://i.ibb.co/Gvh0Gw3/resul.png)

I was very happy in passing the examination but I was more proud that I learnt alot from this course. The learning never stops.

![](https://i.ibb.co/VWz4324/cert.png)
