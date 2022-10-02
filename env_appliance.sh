#!/bin/bash

##################################################
# Technical project data for Alertflex collector #
##################################################

# collector
# work directory and node id and probe id
export INSTALL_PATH=/home/alertflex/altprobe
export PROJECT_ID=60685ae6-1c77-4179-a083-af0179e14058
export NODE_NAME=node01
export HOST_NAME=alertflex

# controller
# url: "ssl://host:61617" or "tcp://host:61616"
export AMQ_URL='tcp:\/\/127.0.0.1:61616'
export AMQ_USER=admin
export AMQ_PWD=Pwd12345
export AMQ_CERT=indef
export CERT_VERIFY=false
export AMQ_KEY=indef
export KEY_PWD=indef

# sources
# if *_LOG is "indef", redis connection will use
export FALCO_LOG=indef
export MODSEC_LOG=indef
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
export WAZUH_USER=wazuh
export WAZUH_PWD=wazuh

# build rpm/deb packages
export BUILD_PACKAGE=no