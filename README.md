The repository includes Alertflex collector and installation scripts for security sensors (Suricata NIDS, Wazuh HIDS, Falco CRS). 

Alertflex collector (Altprobe) is an open-source element of the Alertflex project. Alertflex works as a security event manager and implements CTI, EDR, NTA and SOAR technology stack based on integration with third-party cybersecurity products (more than 20 are integrated at the moment).

![](https://github.com/alertflex/altprobe/blob/master/img/dashboard.png)

The Alertflex is based on five levels of security event management technology: Collection, Streaming, Analysis, Storage, Access. 
For working inside a distributed environment of Hybrid IT, the solution consists of separate software components Collector, Controller, Management Console. 
Collector (Altprobe) is placed in the network domain where security sensors are installed (Container Runtime Security, Host IDS, File Integrity Monitor, 
Network IDS). Together with security sensors, Collector logically forms the Remote node. 

![](https://github.com/alertflex/altprobe/blob/master/img/lld-arch.png)

For more information, please see the [Alertflex project documentation](https://alertflex.org/doc/index.html)

Please [open an issue on GitHub](https://github.com/alertflex/altprobe/issues), if you'd like to report a bug or request a feature. 
Have a question or need tech support, please send an email to address: info@alertflex.org
and join the community via [Alertflex Discord server](https://discord.gg/wDSz7rDMWv)
