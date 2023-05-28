#!/bin/bash

cd $1 && $2/nmap --host_timeout 60 -F -oX nmap.xml $3

logger "altprobe: run of nmap.sh"

