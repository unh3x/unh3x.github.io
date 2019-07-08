---
title: "D-link Central WiFi Manager(CWM-100) Multiple Vulnerabilities"
date: 2019-02-21 00:30:00
---
# **[Vulnerability Description]()**
  **&ensp;&ensp;&ensp;&ensp;D-Link® Central WiFiManager software controller helps network administrators streamline their wireless access point (AP) management workflow. Central WiFi Manager is an innovative approach to the more traditional hardware-based multiple access point management system. It uses a centralized server to both remotely manage and monitor wireless APs on a network. Whether deployed on a local computer or hosted on a public cloud service, Central WiFi Manager can be easily integrated into existing networks in conjunction with supporting D-Link wireless APs, to help eliminate existing bottlenecks for wireless traffic.**

  **&ensp;&ensp;&ensp;&ensp;Vulnerabilities were found in the Central WiFiManager Software Controller, allowing unauthenticated attackers to execute arbitrary SQL command to obtain any data in the database including admin passwords, and could lead to remote code execution. Also SQL injecion and XSS vulnerabilities were found.All of the vulnerabilities found do not require any authorization.**
<BR><BR>
# **[Vulnerable Packages]()**
**&ensp;&ensp;&ensp;&ensp;Central WifiManager Before Ver. 1.03R0100- Beta6**
<BR><BR>
# **[Credits]()**
**&ensp;&ensp;&ensp;&ensp;These vulnerabilities were discovered and researched by M3@ZionLab from DBAppSecurity.**
<BR>
# **[Report Timeline]()**
* **2018-11-19: Sent an initial notification to D-Link, including a draft advisory.**
* **2018-11-20: D-Link replied they were working on new patches to address some security issues and asked the specific version I tested.**
* **2018-11-21: Sent the vulnerability report.**
* **2018-11-21: D-Link informed R&D are in process of a release candidate and my vulnerability fixes wolud be in the next version about 45 days later.**
* **2018-11-24: D-Link informed R&D worked it out and notified me the fixed version will be available on 11/30.**
* **2018-11-30: Sent an email to request a status update**
* **2018-12-01: D-Link sent me a new beta version for test**
* **2018-12-03: Retested the new version and found that R&D has already patched these vulnerabilities**
* **2019-07-09: CVE assigned and make a disclosure.**


<BR>
# **[Disclaimer]()**										
**The author is not responsible for any misuse of the information contained herein and accepts no responsibility for any damage caused by the use or misuse of this information. The author prohibits any malicious use of security related information or exploits by the author or elsewhere.**
