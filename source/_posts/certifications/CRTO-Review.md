---
cover: https://i.ibb.co/tH9xXWW/CRTO-banner.png
title: CRTO (Certified Red Team Operator) Review 
date: 6/26/2024 11:30:00 +06:00
categories: certification-review
tags: [CRTO, Red Teaming, Cobalt Strike]
toc: true
toc_number: false
---

# Introduction

![](https://i.ibb.co/pd4kC45/badge.png)

Last Saturday I passed the Certified Red Team Operator (CRTO) exam, offered by Zero Point Security with all 8/8 flags. I believe Daniel Duggan is the sole founder, maintainer, handles the overall support, discord along with numerous other course offered by Zero Point Security. It was an awesome experience to get hands on experience with cobalt strike. The course costs about £365.00 which is about NPR 64,097.54 about $476.86 USD. The course can be purchased with lab time included or you can purchase the lab time separately. I had purchased the course with 40 hours of lab time which costs £405.00 about NPR 71,121.93 which is about $529 USD capped to 30 days. Remember the lab will expire regardless you use your lab time or not within those 30 days. The course alone does include a free exam attempt. You can however only pay for the exam without purchasing the course if you are a seasoned red teamer. One of the major benefit I wanted to highlight is the fact that the course material is constantly updated and we get to keep the course material for lifetime, while I was doing my lab two new sections **Relaying WebDav** and **Microsoft Configuration Manager** were added into the course. You can find the purchase details below or directly from the zero point security website [Zero Point Security](https://training.zeropointsecurity.co.uk/courses/red-team-ops).

![](https://i.ibb.co/4tzdLgC/course.png)   

# Course Overview

The Red Team Ops course teaches the basic Tools, Techniques and Procedures for adversary simulation and Red Teaming. The entire lab and course is covered using cobalt strike which is one of the industry leading command and control framework. The course covers entire attack lifecycle also known as cyber kill chain from external reconnaissance, initial compromise, maintaining persistence, bypassing numerous defenses, enumerating internal Active Directory network, pivoting, stealing credentials from different workstations/servers, moving laterally to different hosts on a network, performing various Kerberos attacks, Active Directory Certificate Services attacks, attacking misconfigured GPOs, LAPS, SCCM, compromising other forest via inbound and outbound trusts to data hunting and exfiltration all whilst being aware of OPSEC concerns. The entire course curriculum can be found on [Zero Point Security Website](https://training.zeropointsecurity.co.uk/courses/red-team-ops). The course is mainly text based along with code snippets easy to copy and paste. Some important modules does include accompanying videos. I personally felt the course material very easy to understand and follow along, Rasta has covered every TTP in the course in such a way maintaining balance between not diving too deep into any one topic while ensuring we grasp the key concepts of what's happening. Throughout the TTPs Rasta teaches various opsec considerations to keep in mind such as while requesting TGT using ntlm hash or aes256 key `/domain` parameter can be supplied with value of current domain so that the request seems to be originating from the current domain as well as various events which gets triggered during lateral movement, user impersonation and Kerberos attacks.

![](https://i.ibb.co/rMrvzF5/sore.png)
