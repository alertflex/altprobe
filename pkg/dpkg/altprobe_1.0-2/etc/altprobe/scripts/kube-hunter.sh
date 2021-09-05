#!/bin/bash

cd /root/reports && kube-hunter --report json --remote $1 > kube-hunter.json

logger "altprobe: run of kube-hunter.sh"
