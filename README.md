# Alertflex Collector (Altprobe)

Alertflex project is an open-source continuous security monitoring solution designed for use in Hybrid Clouds (on-premises and cloud-based IT infrastructure). By monitoring security events and reports from well-known cybersecurity applications, Alertflex gives companies end-to-end security visibility. The project adapts of third-party software products into a unified solution based on the CTI EDR SOAR technology stack and DevSecOps best practices.

Alertflex requires fewer system resources compared with similar products and mostly integrates of free open-source third-party software. It can significantly reduce costs for your cybersecurity monitoring.

Alertflex implements two main functionality:

**Security event management** for a distributed hub of security sensors (Suricata NIDS, Wazuh HIDS, Falco CRS, Modsecurity WAF) based on the next levels: 
* Collection (Alertflex collector)
* Streaming (ActiveMQ)
* Analysis  (Alertflex controller)
* Storage (MySQL)
* Access  (Alertflex controller and console)

**Security automation and orchestration**
* IDS centralized management for rules, configs, filtering policies, IP address blocking lists
* CTI functions which are based on integration with MISP. Performs a reputation checks for IP addresses, DNS records, MD5, SHA1 SHA256 hashes of files. Creates an alert, in case of suspicious data has been found.
* Can redirect alerts, Netflow, logs  to open-source Log Management and monitoring systems ( Graylog, ElasticStack, Prometheus/Grafana)
* Can periodically run scanning of remote files in Malware Analysis Sandbox (Cuckoo, Hybrid Analysis, VMRay)
* Integrates SAST and DAST tools (Nmap, SonarQube, OWASP ZAP)
* Provides REST API and interface compatible with Open Cybersecurity Alliance ecosystem for IDS alerts

**Altprobe** includes Alertflex collector and installation scripts for security sensors (Suricata NIDS, Wazuh HIDS, Falco CRS). 

For more information, please see the [Alertflex project documentation](https://alertflex.org/doc/index.html)
	
## Support

Please [open an issue on GitHub](https://github.com/alertflex/altprobe/issues), if you'd like to report a bug or request a feature. 
Have a question or need tech support, please send an email to address: info@alertflex.org
	

