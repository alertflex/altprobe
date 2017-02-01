#!/bin/bash
echo "*******************"
echo "* Solution status *"
echo "*******************"
echo 

altprobe status 2>&1
echo
service nprobe status
echo
service suricata status
echo
service ossec status
echo
