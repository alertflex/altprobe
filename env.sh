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
export AMQ_KEY=none
export KEY_PWD=none

# sources
# if *_LOG is "none", redis connection will use
export FALCO_LOG=none
export MODSEC_LOG=none
export SURI_LOG=none
export WAZUH_LOG='\/var\/ossec\/logs\/alerts\/alerts.json'

# install add-on packages
export INSTALL_REDIS=true
export INSTALL_FALCO=true
export INSTALL_SURICATA=true
export INTERFACE=xxx
export INSTALL_WAZUH=true
export WAZUH_USER=foo
export WAZUH_PWD=bar
# filebeat package for transport of alerts from file to redis
export INSTALL_FILEBEAT=false










