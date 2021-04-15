#!/bin/bash

cd /root/reports && nmap --host_timeout 60 -F -oX nmap.xml $1 

logger "altprobe: run of nmap.sh"
