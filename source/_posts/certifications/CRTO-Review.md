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

# Lab Review

The lab was one of the most fun and exciting experience. It consisted of multiple domains spread across different forests. The lab is hosted on Snap Labs and can only be accessed via guacamole and ofc no internet access is present. Each individual systems can also be accessed directly, there is also Kibana instance configured where we can see different event logs for various attacks performed which gives perspective from a blue teamer. Mostly I enjoyed compromising sql server and further compromising linked server in different forest and abusing SCCM which is also known as Microsoft Configuration Manager, this is one of a new attack vector which was really enjoyable. After completing the entire course it is highly recommended to enable windows defender and AppLocker on all servers via GPO and go through the lab one more time. The `Microsoft Defender Antivirus` chapter is one of the most important chapter. It effectively covers every technique of bypassing AV such as modifying artifact kit for exe, dll, service exe payloads, resource kit for powershell, js and in memory execution techniques. It also covers circumventing behavioral detections and various other techniques such as hardware breakpoints for manual amsi bypasses, so do practice this chapter very thoroughly. I believe 40 hours of lab time is enough to once go through the entire course without enabling windows defender and enabling windows defender second time. You can use the extra hours for trying various stuffs creating custom BOF, custom scripts, etc. Also do not forget to complete the challenges as it will benefit a lot during exam.

# Exam Experience

The exam is 48 hours spread across 4 days. You can start and stop the exam environment to preserve the runtime but you need to be mindful to utilize the 48 hours effectively according to your schedule ofc in span of the 4 days. The exam can be booked from the [Booking Page](https://training.zeropointsecurity.co.uk/pages/red-team-ops-exam). I booked my exam for Saturday. Right after booking the exam you will see Red Team Ops exam event on your dashboard with threat profile which provides the information regarding the threat you need to emulate and the objective in order to pass the exam. In order to pass the exam you will need 6 out of 8 flags which needs to be submitted on the respective scoring portal provided. It is highly recommended to spend some time preparing artifact kit, resource kit, checking the payloads if they get detected by AV, hosting various bypasses and required payloads on teamserver. I recommend to prepare your malleable c2 profile during the lab hours itself and check if everything is working correctly. Here is an excellent blog post [Malleable C2](https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2-profile/) for preparing malleable c2 profile. The exam is an assumed breach where we are given an initial workstation with low privileged access. I felt that the AV in the exam was aggressive compared to the lab so prepare accordingly. Moreover everything needed in order to pass the exam is covered in the course material but the exam comes with a slight twist. I already had passing score before 4:00 pm. The final 7th and 8th flags took me alot of time but moreover I got all 8/8 flags before 8:00 pm. I received the badge next day although I had 2 days of exam lab time still remaining.

![](https://i.ibb.co/2MsKh1h/bam2.png)

# Tips and Tricks
- Go through the entire lab with defender and AppLocker enabled
- Prepare your malleable c2 profile during the lab hours itself.
- Spend you initial time during exam on preparing your artifact kit, resource kit and configuring various other bypasses
- Prepare your methodology beforehand and follow along
- Have different methods of achieving same objective

