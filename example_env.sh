#!/bin/bash

##################################################
# Technical project data for Alertflex collector #
##################################################

# collector:
# Project id, work directory and id of node (for project ID use any value in UUID format, but the same such for the controller)
export INSTALL_PATH=/home/alertflex/Altprobe
export PROJECT_ID=nsm_solution
export NODE_ID=collr
export SENSOR_ID=master

export INSTALL_SURICATA=yes
export INTERFACE=eth0
export EXTRACT_FILES=no

export INSTALL_WAZUH=yes
# for communication between altprobe and wazuh server use next account:
export WAZUH_USER=foo
export WAZUH_PWD=bar

# controller:
# NOTE! settings for connection between collector and broker (alertflex controller)
# url: "ssl://host:61617" or "tcp://host:61616"
export AMQ_URL='ssl:\//\af-ctrl:61617'
export AMQ_USER=user1
export AMQ_PWD=Password1234
# if cert, key_pwd are "none", TLS/SSL connection parameters will not in use
export AMQ_CERT='\/etc\/alertflex\/Broker.pem'
export AMQ_KEY='\/etc\/alertflex\/Client.pem'
export KEY_PWD=Password1234

# sources:
# if *_LOG is "none", redis connection will use
export MODSEC_LOG='\/var\/log\/nginx\/error.log'
export SURI_LOG='\/var\/log\/suricata\/eve.json'
export WAZUH_LOG='\/var\/ossec\/logs\/alerts\/alerts.json'

# install filebeat package for transport of alerts from file to redis
export INSTALL_FILEBEAT=no









