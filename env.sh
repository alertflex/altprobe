#!/bin/bash

##################################################
# Technical project data for Alertflex collector #
##################################################

# Project id, work directory and id of node (for project ID use any value in UUID format, but the same such for the controller)
export INSTALL_PATH=/home/alertflex/Altprobe
export PROJECT_ID=16c9d604-2da7-4878-b865-6f7e9ee3a9d4
export NODE_ID=collr
export SENSOR_ID=master

export INSTALL_SURICATA=yes
export INTERFACE=eth0
export EXTRACT_FILES=no

export INSTALL_WAZUH=yes
export WAZUH_USER=foo
export WAZUH_PWD=bar

export INSTALL_FILEBEAT=yes

# NOTE! settings for connection between collector and broker (alertflex controller)
export AMQ_HOST=af-ctrl
export AMQ_USER=client
export AMQ_PWD=*****










