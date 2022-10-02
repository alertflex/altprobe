#!/bin/bash

# load technical project data for Altprobe collector
source ./env.sh

CURRENT_PATH=`pwd`
if [[ $INSTALL_PATH != $CURRENT_PATH ]]
then
	echo "Please change install directory"
	exit 0
fi

echo "*** Installation alertflex collector started***"
sudo add-apt-repository ppa:maxmind/ppa -y
sudo apt-get update
sudo apt-get -y install libpcre3 libpcre3-dbg libpcre3-dev  libnss3-dev libc6-dev libnspr4-dev build-essential autoconf automake libtool libpcap-dev libnet1-dev \
libyaml-0-2 libyaml-dev zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 libmagic-dev libjansson-dev libjansson4 libdaemon-dev libboost-all-dev \
make autoconf autoconf-archive m4 pkg-config git libssl-dev apt-transport-https curl python-simplejson xz-utils libgeoip1 libgeoip-dev geoip-bin
sudo ldconfig

echo "*** installation hiredis***"
git clone https://github.com/redis/hiredis.git
cd hiredis
sudo make
sudo make install
cd ..

echo "*** installation activemq ***"
sudo apt-get -y install apache2-dev libapr1-dev libaprutil1-dev
curl -L -O https://downloads.apache.org/activemq/activemq-cpp/3.9.5/activemq-cpp-library-3.9.5-src.tar.gz
tar xvfz activemq-cpp-library-3.9.5-src.tar.gz
cd activemq-cpp-library-3.9.5
./autogen.sh
./configure --enable-ssl
make
sudo make install
sudo ldconfig
cd ..

echo "*** installation altprobe ***"
cd src
sudo make
sudo make install

sudo sed -i "s/_project_id/$PROJECT_ID/g" /etc/altprobe/filters.json
sudo sed -i "s/_node_name/$NODE_NAME/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_host_name/$HOST_NAME/g" /etc/altprobe/altprobe.yaml
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
sudo curl https://files-cdn.liferay.com/mirrors/geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.xz -o /etc/altprobe/GeoLiteCity.dat.xz
sudo unxz /etc/altprobe/GeoLiteCity.dat.xz

cd ..

if [[ $INSTALL_REDIS == yes ]]
then
	echo "*** installation redis ***"
	sudo apt-get -y install redis-server 
fi

if [[ $INSTALL_FALCO == yes ]]
then
    echo "*** installation falco ***"
	curl -s https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public | sudo apt-key add -
	sudo curl -s -o /etc/apt/sources.list.d/draios.list https://s3.amazonaws.com/download.draios.com/stable/deb/draios.list
	sudo apt-get update
	sudo apt-get -y install linux-headers-$(uname -r)
	sudo apt-get -y install falco
fi

if [[ $INSTALL_SURICATA == yes ]]
then
	sudo add-apt-repository --yes ppa:oisf/suricata-stable
	sudo apt-get update
	sudo apt-get -y install suricata
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
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -i _monitoring_interface
[Install]
WantedBy=multi-user.target
EOF'

	sudo sed -i "s/_monitoring_interface/$SURICATA_INTERFACE/g" /etc/systemd/system/suricata.service
	sudo systemctl enable suricata
fi

if [[ $INSTALL_WAZUH == yes ]]
then
	
	echo "*** installation OSSEC/WAZUH server ***"
	sudo apt-get update
	sudo apt-get -y install curl apt-transport-https lsb-release
	curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
	echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list
	sudo apt-get update
	sudo apt-get -y install wazuh-manager
	sudo systemctl daemon-reload
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

if [[ $BUILD_PACKAGE == yes ]]
then
    cd $INSTALL_PATH/pkg
    sudo chmod u+x dpkg/altprobe_1.0-2/etc/altprobe/scripts/*
    sudo chmod u+x dpkg/altprobe_1.0-2/usr/local/bin/altprob*
    sudo cp -rp dpkg ~
    sudo cp /usr/local/bin/altprobe ~/dpkg/altprobe_1.0-2/usr/local/bin/
    sudo mkdir ~/dpkg/altprobe_1.0-2/usr/local/lib/
    sudo cp /usr/local/lib/libhiredis.so.1.0.3-dev ~/dpkg/altprobe_1.0-2/usr/local/lib/
    sudo cp /usr/local/lib/libactivemq-cpp.so.19.0.5 ~/dpkg/altprobe_1.0-2/usr/local/lib/
    sudo chown -R root:root ~/dpkg
    cd ~/dpkg
    sudo dpkg-deb --build altprobe_1.0-2
fi

