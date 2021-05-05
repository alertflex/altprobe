#!/bin/bash

cd /root/reports && /home/linuxbrew/.linuxbrew/bin/dependency-check --scan $1 -f JSON -o ./

logger "altprobe: run of dependency-check.sh"
