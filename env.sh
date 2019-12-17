#!/bin/bash

##################################################
# Technical project data for Alertflex collector #
##################################################

# collector
# work directory and node id and probe id
export INSTALL_PATH=/home/alertflex/altprobe
export PROJECT_ID=xxxxx
export NODE_ID=xxxxx
export PROBE_ID=xxxxx

# controller
# url: "ssl://host:61617" or "tcp://host:61616"
export AMQ_URL='ssl:\/\/xxxxx:61617'
export AMQ_USER=xxxxx
export AMQ_PWD=*****
export AMQ_CERT='\/etc\/altprobe\/Broker.pem'
export CERT_VERIFY=true
export AMQ_KEY=indef
export KEY_PWD=indef

# sources
# if *_LOG is "indef", redis connection will use
export FALCO_LOG=indef
export MODSEC_LOG=indef
export SURI_LOG=indef
export WAZUH_LOG='\/var\/ossec\/logs\/alerts\/alerts.json'

# install add-on packages
export INSTALL_REDIS=false
export INSTALL_FALCO=false
export INSTALL_SURICATA=false
export INTERFACE=xxx
export INSTALL_WAZUH=true
export WAZUH_USER=foo
export WAZUH_PWD=bar











