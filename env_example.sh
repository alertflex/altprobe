#!/bin/bash

##################################################
# Technical project data for Alertflex collector #
##################################################

# collector
# work directory and node id and probe id
export INSTALL_PATH=/home/alertflex/altprobe
export PROJECT_ID=0ca7e3b3-1a0c-407a-957d-aab039165217
export VRN_ID=vrn01
export HOST_NAME=collr01

# controller
# url: "ssl://host:61617" or "tcp://host:61616"
export AMQ_URL='ssl:\/\/af-ctrl:61617'
export AMQ_USER=admin
export AMQ_PWD=Pwd12345
export AMQ_CERT='\/etc\/altprobe\/Broker.pem'
# in case problem with SSL it can be set to false as temporary solution
export CERT_VERIFY=true
export AMQ_KEY=indef
export KEY_PWD=indef

# probes
export RESULT_PATH='\/home\/alertflex\/reports'
export TRIVY_PATH='\/usr\/bin'
export FALCO_LOG='\/var\/log\/falco.json'
export MODSEC_LOG=indef
export SURI_LOG='\/var\/log\/suricata\/eve.json'
export WAZUH_LOG='\/var\/ossec\/logs\/alerts\/alerts.json'

# install add-on packages
export INSTALL_REDIS=yes
export REDIS_HOST=127.0.0.1
export INSTALL_TRIVY=yes
export INSTALL_FALCO=no
export INSTALL_SURICATA=yes
export SURICATA_INTERFACE=enp0s8
export INSTALL_WAZUH=yes
export WAZUH_HOST=127.0.0.1
export WAZUH_USER=wazuh
export WAZUH_PWD=wazuh

# build rpm/deb packages
export BUILD_PACKAGE=no

