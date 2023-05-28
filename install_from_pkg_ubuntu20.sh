#!/bin/bash

# load technical project data for Altprobe collector
source ./env.sh

CURRENT_PATH=`pwd`
if [[ $INSTALL_PATH != $CURRENT_PATH ]]
then
	echo "Please change install directory"
	exit 0
fi

sudo mkdir -p  ${RESULT_PATH//'\'}

echo "*** Installation alertflex collector started***"
sudo add-apt-repository ppa:maxmind/ppa -y
sudo apt-get update
sudo apt-get -y install libpcre3 libpcre3-dbg libpcre3-dev  libnss3-dev libc6-dev libnspr4-dev build-essential autoconf automake libtool libpcap-dev libnet1-dev \
libcurl4-openssl-dev uncrustify cmake zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 libmagic-dev libjansson-dev libjansson4 libdaemon-dev libboost-all-dev \
make autoconf autoconf-archive m4 pkg-config git libssl-dev apt-transport-https curl python-simplejson xz-utils libgeoip1 libgeoip-dev geoip-bin \
libapr1 libapr1-dev libsctp-dev libsctp1 libyaml-dev uuid-dev

sudo ldconfig

sudo dpkg -i ./pkg/altprobe_1.0-3.deb

sudo ldconfig

echo "*** configure altprobe ***"

sudo sed -i "s/_project_id/$PROJECT_ID/g" /etc/altprobe/filters.json
sudo sed -i "s/_vrn_id/$VRN_ID/g" /etc/altprobe/altprobe.yaml
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
sudo sed -i "s/_result_path/$RESULT_PATH/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_trivy_path/$TRIVY_PATH/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_falco_log/$FALCO_LOG/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_modsec_log/$MODSEC_LOG/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_suri_log/$SURI_LOG/g" /etc/altprobe/altprobe.yaml
sudo sed -i "s/_wazuh_log/$WAZUH_LOG/g" /etc/altprobe/altprobe.yaml

sudo chmod go-rwx /etc/altprobe/altprobe.yaml
sudo curl https://files-cdn.liferay.com/mirrors/geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.xz -o /etc/altprobe/GeoLiteCity.dat.xz
sudo unxz /etc/altprobe/GeoLiteCity.dat.xz

if [[ $INSTALL_REDIS == yes ]]
then
	echo "*** installation redis ***"
	sudo apt-get -y install redis-server 
fi

if [[ $INSTALL_TRIVY == yes ]]
then
	echo "*** installation trivy ***"
	sudo apt-get install wget apt-transport-https gnupg lsb-release
	wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
	echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
	sudo apt-get update
	sudo apt-get install trivy
fi

if [[ $INSTALL_FALCO == yes ]]
then
    echo "*** installation falco ***"
	curl -s https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public | sudo apt-key add -
	sudo curl -s -o /etc/apt/sources.list.d/draios.list https://s3.amazonaws.com/download.draios.com/stable/deb/draios.list
	sudo apt-get update
	sudo apt-get -y install linux-headers-$(uname -r)
	sudo apt-get -y install falco
	sudo cp ./configs/falco.yaml /etc/falco/
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
	sudo cp ./configs/wazuh_api.yaml /var/ossec/api/configuration/api.yaml
	sudo sed -i "s/_wazuh_user/$WAZUH_USER/g" /etc/altprobe/altprobe.yaml
	sudo sed -i "s/_wazuh_pwd/$WAZUH_PWD/g" /etc/altprobe/altprobe.yaml
	
sudo bash -c 'cat << EOF > /etc/systemd/system/altprobe.service
[Unit]
Description=Altprobe
After=wazuh-manager.service
[Service]
Type=forking
User=root
ExecStart=/usr/sbin/altprobe start
ExecStop=/usr/sbin/altprobe stop
ExecReload=/usr/sbin/altprobe-restart
PIDFile=/run/altprobe.pid
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
ExecStart=/usr/sbin/altprobe start
ExecStop=/usr/sbin/altprobe stop
ExecReload=/usr/sbin/altprobe-restart
PIDFile=/run/altprobe.pid
Restart=on-failure
RestartSec=30s
[Install]
WantedBy=multi-user.target
EOF'
fi

sudo systemctl daemon-reload
sudo systemctl enable altprobe.service
