#!/bin/bash

#load technical project data for Alertflex collector
source ./env.sh

CURRENT_PATH=`pwd`
if [[ $INSTALL_PATH != $CURRENT_PATH ]]
then
    echo "Please change install directory"
    exit 0
fi

echo "*** Installation alertflex collector started***"

sudo bash -c 'echo "Defaults timestamp_timeout=50" >> /etc/sudoers.d/99_sudo_include_file'

sudo amazon-linux-extras enable epel redis6
sudo yum clean metadata

echo "*** install packages  ***"
sudo yum -y install epel-release redis autoconf automake gcc make gcc-c++ git libtool libyaml libyaml-devel zlib zlib-devel boost-devel boost-thread libdaemon-devel openssl-libs openssl-devel apr-devel hiredis hiredis-devel

sudo yum -y update

git clone https://gitbox.apache.org/repos/asf/activemq-cpp.git 

cd activemq-cpp/activemq-cpp
./autogen.sh
./configure --enable-ssl
make
sudo make install

sudo ln -s /usr/local/lib/libactivemq-cpp.so.20 /usr/lib/libactivemq-cpp.so.20
sudo ldconfig

echo "*** installation altprobe ***"
cd ~/altprobe/src

sudo cp ../configs/ec2ami_configurations.xml ./nbproject/configurations.xml
sudo cp ../configs/ec2ami_Makefile-Debug.mk ./nbproject/Makefile-Debug.mk
sudo sed -i "s|activemq-cpp-3.9.5|activemq-cpp-3.10.0|g" ./controller.cpp

make
sudo make install
sudo mkdir -pv /etc/altprobe/

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

sudo ln -s /usr/local/bin/altprobe /usr/sbin/altprobe
sudo ln -s /usr/local/bin/altprobe-restart /usr/sbin/altprobe-restart
sudo ln -s /usr/local/bin/altprobe-start /usr/sbin/altprobe-start
sudo ln -s /usr/local/bin/altprobe-status /usr/sbin/altprobe-status
sudo ln -s /usr/local/bin/altprobe-stop /usr/sbin/altprobe-stop
cd ..

if [[ $INSTALL_FALCO == yes ]]
then
    echo "*** installation falco ***"
    sudo rpm --import https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public
	sudo curl -s -o /etc/yum.repos.d/draios.repo https://s3.amazonaws.com/download.draios.com/stable/rpm/draios.repo
	sudo yum -y install kernel-devel-$(uname -r)
	sudo yum -y install falco
fi

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
	sudo systemctl enable wazuh-manager

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

sudo rm /etc/sudoers.d/99_sudo_include_file

if [[ $BUILD_PACKAGE == yes ]]
then
	cd $INSTALL_PATH/pkg
	sudo yum -y install rpm-build rpmdevtools
    sudo cp -rp rpmbuild /root/
    sudo cp /usr/local/bin/altprobe /root/rpmbuild/SOURCES/
	sudo cp /usr/local/lib/libactivemq-cpp.so.20 /root/rpmbuild/SOURCES/
    sudo chown -R root:root /root/rpmbuild
    sudo rpmbuild -ba /root/rpmbuild/SPECS/altprobe-1.0.spec
	sudo cp /root/rpmbuild/RPMS/x86_64/altprobe-1.0-1.amzn2.x86_64.rpm $INSTALL_PATH
	sudo chmod ec2-user:ec2-user $INSTALL_PATH/altprobe-1.0-1.amzn2.x86_64.rpm
fi



