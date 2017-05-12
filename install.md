## Installation steps for Altprobe/IDS
This installation procedure was tested on Ubuntu 14.04 under VirtualBox
</br>For network interface configuration (sniffing mode), please see link:
https://github.com/Security-Onion-Solutions/security-onion/wiki/NetworkConfiguration
<br/>NOTE! Make a promisc interface name a visible for installation scripts by ``export MON_INTERFACE=ethXX``

### install Altprobe
```
sudo apt-get -y install git
git clone git://github.com/olegzhr/altprobe.git
sudo bash ./altprobe/scripts/altprobe_install.sh
```

### install Wazuh IDS

For check of installation parameters, see file ``./altprobe/config/sensors-config/preloaded-vars.conf`` 

```
git clone -b stable https://github.com/alertflex/wazuh.git
cd wazuh
sed -i 's/USE_ZEROMQ?=no/USE_ZEROMQ?=yes/g' ./src/Makefile
sudo cp ../altprobe/config/sensors-config/preloaded-vars.conf ./etc/
sudo ./install.sh
cd ..
```
after installation, add interface ZeroMQ in file ``/var/ossec/etc/ossec.conf`` for output to Altprobe collector
<br/>NOTE! Examples of configs parameters can be found in folder [config](config/sensors-config) this github repository.

### install Suricata IDS 
NOTE! Choose version of Suricata by ``export SURICATA_VER=3.1.1``
```
wget "http://www.openinfosecfoundation.org/download/suricata-$SURICATA_VER.tar.gz" 
tar -xvzf "suricata-$SURICATA_VER.tar.gz" 
cd "suricata-$SURICATA_VER"
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-libjansson
sudo make
sudo make install-full
sudo ldconfig
cd ..
```

```
sudo bash -c 'cat << EOF > /etc/init/suricata.conf
# suricata
description "Intruder Detection System Daemon" 
start on runlevel [2345]
stop on runlevel [!2345]
respawn
expect fork
exec suricata -D --pidfile /var/run/suricata.pid -c /etc/suricata/suricata.yaml -i INTERFACE
EOF'
```

```
sudo sed -i "s/INTERFACE/$MON_INTERFACE/g" /etc/init/suricata.conf
sudo touch /etc/init/suricata.override
sudo sh -c 'echo "manual" > /etc/init/suricata.override'
```
after installation, enable Unix dtgram sockets in file ``/etc/suricata/suricata.yaml`` for output to Altprobe collector 

### install nProbe 
NOTE! Please, see link http://www.nmon.net/apt-stable/

### startup configuration

For running Suricata and Altprobe on startup, please, add in file ``/etc/rc.local`` the next two strings (before string "exit 0") : 
```
/usr/local/bin/altprobe start
service suricata start
```











