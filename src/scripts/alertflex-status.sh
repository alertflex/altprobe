#!/bin/bash
echo "**********************************"
echo "* Status of alertflex local node *"
echo "**********************************"
echo
altprobe status
echo
service activemq status
echo
service suricata status
echo
/var/ossec/bin/ossec-control status
echo
