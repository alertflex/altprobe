#!/bin/bash

##################################################
# Technical project data for Alertflex collector #
##################################################

# collector
# work directory and node id and probe id
export INSTALL_PATH=/home/xxxxx/altprobe
export PROJECT_ID=xxxxx
export VRN_ID=xxxxx
export HOST_NAME=xxxxx

# controller
# url: "ssl://host:61617" or "tcp://host:61616"
export AMQ_URL='ssl:\/\/xxxxx:61617'
export AMQ_USER=xxxxx
export AMQ_PWD=*****
export AMQ_CERT='\/etc\/altprobe\/Broker.pem'
export CERT_VERIFY=true
export AMQ_KEY=indef
export KEY_PWD=indef

# probes
export RESULT_PATH='\/home\/xxxxx\/reports'
export TRIVY_PATH=indef
export FALCO_LOG=indef
export MODSEC_LOG=indef
export SURI_LOG=indef
export WAZUH_LOG=indef

# install add-on packages
export INSTALL_REDIS=no
export REDIS_HOST=127.0.0.1
export INSTALL_TRIVY=no
export INSTALL_FALCO=no
export INSTALL_SURICATA=no
export SURICATA_INTERFACE=xxx
export INSTALL_WAZUH=no
export WAZUH_HOST=indef
export WAZUH_USER=wazuh
export WAZUH_PWD=wazuh

# build rpm/deb packages
export BUILD_PACKAGE=no











