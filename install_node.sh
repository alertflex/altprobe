#!/bin/bash

# load technical project data for Alertflex collector
source ./tpd.sh

CURRENT_PATH=`pwd`
if [ $INSTALL_PATH != $CURRENT_PATH ]
then
	echo "Please change install directory"
	exit 0
fi

echo "*** Installation alertflex collector started***"
sudo add-apt-repository ppa:maxmind/ppa -y
sudo apt-get update
sudo apt-get -y install libpcre3 libpcre3-dbg libpcre3-dev  libnss3-dev libc6-dev libnspr4-dev build-essential autoconf automake libtool libpcap-dev libnet1-dev \
libyaml-0-2 libyaml-dev zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 libmagic-dev libjansson-dev libjansson4 libdaemon-dev libgeoip1 libgeoip-dev geoip-bin libboost-all-dev \
make autoconf autoconf-archive m4 pkg-config git libssl-dev apt-transport-https redis-server curl
sudo ldconfig

echo "*** installation hiredis***"
git clone git://github.com/redis/hiredis.git
cd hiredis
sudo make
sudo make install
cd ..

echo "*** installation zeromq ***"
sudo apt-get -y install libzmq3-dev
wget http://download.zeromq.org/czmq-2.2.0.tar.gz --no-check-certificate
tar xfz czmq-2.2.0.tar.gz
cd czmq-2.2.0
./configure
sudo make all -j
sudo make install
cd ..

echo "*** installation activemq ***"
sudo apt-get -y install apache2-dev libapr1-dev libaprutil1-dev
git clone https://git-wip-us.apache.org/repos/asf/activemq-cpp.git
cd activemq-cpp/activemq-cpp
./autogen.sh
./configure --enable-ssl
make
sudo make install
cd ../..

echo "*** installation altprobe ***"
cd src
sudo make
sudo make install

if [ $AMQ_PWD != none ]
then
	sudo cp ./etc/alertflex-ssl.yaml /etc/alertflex/alertflex.yaml
	sudo sed -i "s/_amq_pwd/$AMQ_PWD/g" /etc/alertflex/alertflex.yaml
	sudo sed -i "s/_amq_host/$AMQ_BROKER/g" /etc/alertflex/alertflex.yaml
fi

sudo sed -i "s/_node_id/$NODE_ID/g" /etc/alertflex/alertflex.yaml
sudo chmod go-rwx /etc/alertflex/alertflex.yaml
sudo cp ../configs/rc.local /etc/

cd ..

if [ $INSTALL_SURICATA == yes ]
then
	echo "*** installation suricata ***"
	wget "http://www.openinfosecfoundation.org/download/suricata-4.0.0.tar.gz"
	tar -xvzf suricata-4.0.0.tar.gz
	cd suricata-4.0.0
	autoreconf -f -i
	./configure --enable-hiredis --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-libjansson --with-libnss-libraries=/usr/lib --with-libnss-includes=/usr/include/nss/ --with-libnspr-libraries=/usr/lib --with-libnspr-includes=/usr/include/nspr
	sudo make
	sudo make install-full
	sudo ldconfig
	cd ..
	sudo bash -c 'cat << EOF > /etc/init/suricata.conf
# suricata
description "Intruder Detection System Daemon" 
start on runlevel [2345]
stop on runlevel [!2345]
respawn
expect fork
exec suricata -D --pidfile /var/run/suricata.pid -c /etc/suricata/suricata.yaml -i _monitoring_interface
EOF'
	sudo sed -i "s/_monitoring_interface/$INTERFACE/g" /etc/init/suricata.conf
	if [ $EXTRACT_FILES == yes ]
	then
		sudo cp ./configs/suricata-files.yaml /etc/suricata/suricata.yaml
		sudo cp ./configs/files.rules /etc/suricata/rules
	else
		sudo cp ./configs/suricata.yaml /etc/suricata/
	fi
fi

if [ $INSTALL_OSSEC == yes ]
then
	echo "*** installation OSSEC ***"
	curl -Ls https://github.com/wazuh/wazuh/archive/v2.1.0.tar.gz | tar zx
	cd wazuh-*
	sed -i 's/USE_ZEROMQ?=no/USE_ZEROMQ?=yes/g' ./src/Makefile
	sudo cp ../configs/preloaded-vars.conf ./etc/
	# WARNING - cycle can happen if something wrong with command "cd wazuh-*"
	sudo ./install.sh
	sudo cp ../configs/ossec.conf /var/ossec/etc/ossec.conf
fi
cd ..



