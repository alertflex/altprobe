The repository includes Alertflex collector and installation scripts for security sensors (Suricata NIDS, Wazuh HIDS, Falco CRS). 

Alertflex is a cybersecurity solution for automation, continuous monitoring, orchestration, threat detection and response. Alertflex works as a Security Events Manager with SOAR capabilities and designed for use in Hybrid IT infrastructure (on-premises and cloud-based).

Project mostly integrates free open-source security software and requires fewer system resources compared with similar products. Supports different sources of security events and reports: Windows, Linux, Docker, Kubernetes, Amazon AWS.

![](https://github.com/alertflex/altprobe/blob/master/img/dashboard.png)

For working inside a distributed environment of Hybrid IT, the solution consists of separate software components Collector, Controller, Management Console. 
Alertfle Collector (Altprobe) is placed in the network domain where security sensors are installed (Container Runtime Security, Host IDS, File Integrity Monitor, 
Network IDS). Together with security sensors, Collector logically forms the Remote node. 

![](https://github.com/alertflex/altprobe/blob/master/img/lld-arch.png)

For more information, please see the [solution description](https://www.alertflex.org/solution.html) and [project documentation](https://alertflex.org/doc/index.html)

Please [open an issue on GitHub](https://github.com/alertflex/altprobe/issues), if you'd like to report a bug or request a feature. 
Have a question or need tech support, please send an email to address: info@alertflex.org
and join the community via [Alertflex Discord server](https://discord.gg/wDSz7rDMWv)
