#!/bin/bash

#load technical project data for Alertflex collector
source ./env.sh

CURRENT_PATH=`pwd`
if [ $INSTALL_PATH != $CURRENT_PATH ]
then
    echo "Please change install directory"
    exit 0
fi

echo "*** Installation alertflex collector started***"
sudo yum -y install epel-release
sudo yum -y update
sudo yum -y install pcre pcre2 autoconf automake gcc make libtool libnet-devel libyaml libyaml-devel zlib zlib-devel libcap-ng file-libs libdaemon-devel GeoIP GeoIP-devel GeoIP-data boost-devel boost-thread libmicrohttpd logrotate autoconf-archive m4 git ntp openssl-libs openssl-devel curl ldconfig

echo "*** installation redis and hiredis lib***"
sudo yum -y install redis hiredis hiredis-devel
sudo systemctl enable redis

echo "*** installation activemq ***"
sudo yum -y install httpd-devel libapreq2-devel apr-util apr-util-devel java-1.8.0-openjdk activemq-cpp.x86_64 activemq-cpp-devel.x86_64

echo "*** installation altprobe ***"
cd ~/Altprobe/src

sudo sed -i "s|activemq-cpp-3.10.0|activemq-cpp-3.9.3|g" ./controller.cpp
export OLD_STR=usr/local/include/activemq-cpp-3.10.0
export NEW_STR=usr/include/activemq-cpp-3.9.3
sudo sed -i "s|$OLD_STR|$NEW_STR|g" ./nbproject/configurations.xml
sudo sed -i "s|$OLD_STR|$NEW_STR|g" ./nbproject/Makefile-Debug.mk
export OLD_STR=usr/include/apr-1.0
export NEW_STR=usr/include/apr-1
sudo sed -i "s|$OLD_STR|$NEW_STR|g" ./nbproject/configurations.xml
sudo sed -i "s|$OLD_STR|$NEW_STR|g" ./nbproject/Makefile-Debug.mk
export OLD_STR=usr/local/include/hiredis
export NEW_STR=usr/include/hiredis
sudo sed -i "s|$OLD_STR|$NEW_STR|g" ./nbproject/configurations.xml
sudo sed -i "s|$OLD_STR|$NEW_STR|g" ./nbproject/Makefile-Debug.mk

sudo make
sudo make install
sudo mkdir -pv /etc/alertflex/

if [ $AMQ_PWD != none ]
then
    sudo cp ./etc/alertflex-ssl.yaml /etc/alertflex/alertflex.yaml
    sudo sed -i "s/_amq_pwd/$AMQ_PWD/g" /etc/alertflex/alertflex.yaml
    sudo sed -i "s/_amq_host/$AMQ_BROKER/g" /etc/alertflex/alertflex.yaml
fi

sudo sed -i "s/_node_id/$NODE_ID/g" /etc/alertflex/alertflex.yaml
sudo chmod go-rwx /etc/alertflex/alertflex.yaml

sudo bash -c 'cat << EOF > /lib/systemd/system/altprobe.service
[Unit]
Description=Altprobe
After=syslog.target network-online.target

[Service]
Type=forking
User=root
ExecStart=/usr/local/bin/altprobe start

[Install]
WantedBy=multi-user.target
EOF'

sudo systemctl enable altprobe

cd ..

if [ $INSTALL_SURICATA == yes ]
then
    echo "*** installation suricata ***"
    sudo yum -y install libpcap-devel pcre-devel libyaml-devel file-devel jansson-devel nss-devel libcap-ng-devel libnet-devel tar libnetfilter_queue-devel lua-devel libpcap-devel pcre-devel libyaml-devel file-devel mariadb-devel jansson-devel nss-devel libcap-ng-devel libnet-devel libnetfilter_queue-devel ethtool libpcap libpcap-devel file-devel libcap-ng-devel

	wget "http://www.openinfosecfoundation.org/download/suricata-4.0.3.tar.gz"
	tar -xvzf suricata-4.0.3.tar.gz
	cd suricata-4.0.3
	autoreconf -f -i
	./configure --enable-hiredis --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-libjansson --with-libnss-libraries=/usr/lib --with-libnss-includes=/usr/include/nss/ --with-libnspr-libraries=/usr/lib --with-libnspr-includes=/usr/include/nspr
	sudo make
	sudo make install-full
	sudo ldconfig
	cd ..
	sudo bash -c 'cat << EOF > /lib/systemd/system/suricata.service
[Unit]
Description=Suricata Intrusion Detection Service
After=syslog.target network-online.target

[Service]
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -i _monitoring_interface

[Install]
WantedBy=multi-user.target
EOF'
	sudo sed -i "s/_monitoring_interface/$INTERFACE/g" /lib/systemd/system/suricata.service
	if [ $EXTRACT_FILES == yes ]
	then
		sudo cp ./configs/suricata-files.yaml /etc/suricata/suricata.yaml
		sudo cp ./configs/files.rules /etc/suricata/rules
	else
		sudo cp ./configs/suricata.yaml /etc/suricata/
	fi
	
	sudo systemctl enable suricata
fi

if [ $INSTALL_WAZUH == yes ]
then

	echo "*** installation OSSEC/WAZUH server ***"
	sudo bash -c 'cat > /etc/yum.repos.d/wazuh.repo <<\EOF
[wazuh_repo]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/3.x/yum/
protect=1
EOF'
    sudo yum -y install wazuh-manager
	sudo systemctl enable wazuh-manager

	echo "*** installation  Wazuh API***"
	curl --silent --location https://rpm.nodesource.com/setup_8.x | bash -
	sudo yum -y install nodejs
	sudo yum -y install wazuh-api
	sudo systemctl enable wazuh-api
	sudo sed -i "s/_wazuh_user/$WAZUH_USER/g" /etc/alertflex/alertflex.yaml
	sudo sed -i "s/_wazuh_pwd/$WAZUH_PWD/g" /etc/alertflex/alertflex.yaml

	echo "*** installation filebeat***"
	curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-6.5.1-x86_64.rpm
	sudo rpm -vi filebeat-6.5.1-x86_64.rpm
	sudo cp ./configs/filebeat.yml /etc/filebeat/
	sudo systemctl enable filebeat
fi
cd ..