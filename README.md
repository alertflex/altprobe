The functionality of the Alertflex project can be considered as XDR, also it is close to the definitions of Cloud Workload Protection Platform (CWPP), Cloud Security Posture Management (CSPM), and SOAR. Alertflex integrates mostly free open source projects (more than 30 at this moment) and AWS cloud cybersecurity services.

![](https://github.com/alertflex/cnode/blob/master/img/hld-arch.jpg)

![](https://github.com/alertflex/cnode/blob/master/img/slides.gif)

The project was tested for small size organizations and can keep a stream of security events 50 EPS and high (required 8 Gb minimum memory for central node). If you want to try Alertflex for a large organization with a high load of events and many running automation playbooks, it should be possible as well, due to Alertflex software components can be split into microservices.

This repository includes Alertflex collector source code and installation script for collector and security sensors (Falco CRS, Suricata NIDS, Wazuh HIDS).

For more information, please see [solution description](https://alertflex.github.io/solution.html) and [project documentation](https://alertflex.github.io/doc/index.html)

Please [open an issue on GitHub](https://github.com/alertflex/altprobe/issues), if you'd like to report a bug or request a feature. 
Have a question or need tech support, please send an email to address: info@alertflex.org
and join the community via [Alertflex Discord server](https://discord.gg/wDSz7rDMWv)
