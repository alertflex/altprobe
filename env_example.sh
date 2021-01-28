#!/bin/bash

##################################################
# Technical project data for Alertflex collector #
##################################################

# collector
# work directory and node id and probe id
export INSTALL_PATH=/home/alertflex/altprobe
export PROJECT_ID=1af11399-0cef-45be-b579-ef6e580a7bf2
export NODE_ID=collr
export PROBE_ID=master

# controller
# url: "ssl://host:61617" or "tcp://host:61616"
export AMQ_URL='ssl:\//\af-ctrl:61617'
export AMQ_USER=user1
export AMQ_PWD=Password1234
export AMQ_CERT='\/etc\/altprobe\/Broker.pem'
export CERT_VERIFY=true
export AMQ_KEY='\/etc\/altprobe\/Client.pem'
export KEY_PWD=Password1234

# sources:
# if *_LOG is "indef", redis connection will use
export FALCO_LOG='\/var\/log\/falco.json'
export SURI_LOG='\/var\/log\/suricata\/eve.json'
export WAZUH_LOG='\/var\/ossec\/logs\/alerts\/alerts.json'

# install add-on packages
export INSTALL_REDIS=yes
export REDIS_HOST=127.0.0.1
export INSTALL_FALCO=no
export INSTALL_SURICATA=yes
export SURICATA_INTERFACE=enp0s3
export INSTALL_WAZUH=yes
export WAZUH_HOST=127.0.0.1
export WAZUH_USER=foo
export WAZUH_PWD=bar

# build rpm/deb packages
export BUILD_PACKAGE=no

