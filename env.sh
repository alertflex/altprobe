#!/bin/bash

##################################################
# Technical project data for Alertflex collector #
##################################################

# Project id, work directory and id of node (for project ID use any value in UUID format, but the same such for the controller)
export PROJECT_ID=16c9d604-2da7-4878-b865-6f7e9ee3a9d4
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








