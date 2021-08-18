#!/bin/bash

#load technical project data for Alertflex collector
source ./env_ami.sh

export INSTALL_PATH=/home/ec2-user/altprobe
export NODE_ID=node01
export PROBE_ID=probe01
export AMQ_URL='tcp:\/\/127.0.0.1:61616'
export AMQ_USER=admin
export AMQ_CERT=indef
export CERT_VERIFY=false
export AMQ_KEY=indef
export KEY_PWD=indef
export FALCO_LOG=indef
export MODSEC_LOG=indef
export INSTALL_WAZUH=yes
export WAZUH_LOG='\/var\/ossec\/logs\/alerts\/alerts.json'
export WAZUH_HOST=127.0.0.1
export WAZUH_USER=wazuh
export WAZUH_PWD=wazuh
export INSTALL_SURICATA=yes
export SURI_LOG='\/var\/log\/suricata\/eve.json'
export SURICATA_INTERFACE=eth1
export INSTALL_REDIS=yes


CURRENT_PATH=`pwd`
if [[ $INSTALL_PATH != $CURRENT_PATH ]]
then
    echo "Please change install directory"
    exit 0
fi

echo "*** Installation alertflex collector started***"

sudo yum -y update

echo "*** installation activemq ***"
sudo yum -y install apr-devel boost-devel boost-thread

if [[ $INSTALL_REDIS == yes ]]
then
     echo "*** installation redis ***"
     sudo yum -y install redis 
     sudo sed -i "s/bind 127.0.0.1/bind 0.0.0.0/g" /etc/redis.conf
     sudo systemctl enable redis
     sudo systemctl start redis
fi

sudo curl -L -O "https://download-ib01.fedoraproject.org/pub/epel/7/x86_64/Packages/h/hiredis-0.12.1-2.el7.x86_64.rpm"
sudo rpm -i hiredis-0.12.1-2.el7.x86_64.rpm
sudo curl -L -O "https://download-ib01.fedoraproject.org/pub/epel/7/x86_64/Packages/h/hiredis-devel-0.12.1-2.el7.x86_64.rpm"
sudo rpm -i hiredis-devel-0.12.1-2.el7.x86_64.rpm
sudo curl -L -O "https://github.com/alertflex/altprobe/releases/download/v1.0.1/altprobe-1.0-1.amzn2.x86_64.rpm"
sudo rpm -i altprobe-1.0-1.amzn2.x86_64.rpm
sudo ldconfig
sudo yum -y update

sudo sed -i "s/_project_id/$PROJECT_ID/g" /etc/altprobe/filters.json
sudo sed -i "s/_node_id/$NODE_ID/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_probe_id/$PROBE_ID/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_redis_host/$REDIS_HOST/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_wazuh_host/$WAZUH_HOST/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_wazuh_user/$WAZUH_USER/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_wazuh_pwd/$WAZUH_PWD/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_amq_url/$AMQ_URL/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_amq_user/$AMQ_USER/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_amq_pwd/$AMQ_PWD/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_amq_cert/$AMQ_CERT/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_cert_verify/$CERT_VERIFY/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_amq_key/$AMQ_KEY/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_key_pwd/$KEY_PWD/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_falco_log/$FALCO_LOG/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_modsec_log/$MODSEC_LOG/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_suri_log/$SURI_LOG/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_wazuh_log/$WAZUH_LOG/g" /etc/altprobe/altprobe.yaml

sudo chmod go-rwx /etc/altprobe/altprobe.yaml

sudo ln -s /usr/sbin/altprobe /usr/local/bin/altprobe
sudo ln -s /usr/sbin/altprobe-restart /usr/local/bin/altprobe-restart 
sudo ln -s /usr/sbin/altprobe-start /usr/local/bin/altprobe-start 
sudo ln -s /usr/sbin/altprobe-status /usr/local/bin/altprobe-status
sudo ln -s /usr/sbin/altprobe-stop /usr/local/bin/altprobe-stop 

if [[ $INSTALL_SURICATA == yes ]]
then
    echo "*** installation suricata ***"
    sudo yum -y install suricata
    sudo cp ./configs/suricata.yaml /etc/suricata/
	
    sudo suricata-update enable-source oisf/trafficid
    sudo suricata-update enable-source et/open
    sudo suricata-update enable-source ptresearch/attackdetection
    sudo suricata-update update-sources
    sudo suricata-update
	
    sudo bash -c 'cat << EOF > /etc/systemd/system/suricata.service
[Unit]
Description=Suricata Intrusion Detection Service
After=syslog.target network-online.target

[Service]
ExecStart=/usr/sbin/suricata -c /etc/suricata/suricata.yaml -i _monitoring_interface

[Install]
WantedBy=multi-user.target
EOF'
    sudo sed -i "s/_monitoring_interface/$SURICATA_INTERFACE/g" /etc/systemd/system/suricata.service
    sudo systemctl enable suricata
    sudo systemctl start suricata
fi

if [[ $INSTALL_WAZUH == yes ]]
then

    echo "*** installation OSSEC/WAZUH server ***"
    sudo bash -c 'cat > /etc/yum.repos.d/wazuh.repo <<\EOF
[wazuh_repo]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF'
    sudo yum -y install wazuh-manager
    sudo sed -i "s/_wazuh_user/$WAZUH_USER/g" /etc/altprobe/altprobe.yaml
    sudo sed -i "s/_wazuh_pwd/$WAZUH_PWD/g" /etc/altprobe/altprobe.yaml
    sudo bash -c 'cat << EOF > /var/ossec/api/configuration/api.yaml
host: 127.0.0.1

https:
  enabled: no
  
# Enable remote commands
remote_commands:
  localfile:
    enabled: yes
    exceptions: []
EOF'
    sudo systemctl enable wazuh-manager
    sudo systemctl start wazuh-manager

    sudo bash -c 'cat << EOF > /etc/systemd/system/altprobe.service
[Unit]
Description=Altprobe
After=wazuh-manager.service
[Service]
Type=forking
User=root
ExecStart=/usr/local/bin/altprobe start
ExecStop=/usr/local/bin/altprobe stop
ExecReload=/usr/local/bin/altprobe-restart
PIDFile=/var/run/altprobe.pid
Restart=on-failure
RestartSec=30s
[Install]
WantedBy=multi-user.target
EOF'
else
    sudo bash -c 'cat << EOF > /etc/systemd/system/altprobe.service
[Unit]
Description=Altprobe
After=network-online.target
[Service]
Type=forking
User=root
ExecStart=/usr/local/bin/altprobe start
ExecStop=/usr/local/bin/altprobe stop
ExecReload=/usr/local/bin/altprobe-restart
PIDFile=/var/run/altprobe.pid
Restart=on-failure
RestartSec=30s
[Install]
WantedBy=multi-user.target
EOF'
fi

sudo systemctl daemon-reload
sudo systemctl enable altprobe.service
sudo systemctl start altprobe.service

rm -r /home/ec2-user/altprobe

exit 0






