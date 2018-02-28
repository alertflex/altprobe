#!/bin/bash

##################################################
# Technical project data for Alertflex collector #
##################################################

export INSTALL_PATH=/home/alertflex/Altprobe
export NODE_ID=collr

export INSTALL_SURICATA=yes
export INTERFACE=eth0
export EXTRACT_FILES=no

export INSTALL_WAZUH=yes
export WAZUH_USER=foo
export WAZUH_PWD=bar

# if AMQ_PWD=none, ssl connection between collector and controller is disabled
# NOTE! in case ssl enabled, use AMQ_PWD with same value as in file tpd.sh from controller installation forlder
export AMQ_PWD=*****
# NOTE! add hostname/dns name of broker (alertflex controller)
export AMQ_BROKER=af-ctrl








