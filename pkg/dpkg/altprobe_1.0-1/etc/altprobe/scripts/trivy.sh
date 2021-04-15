#!/bin/bash

cd /root/reports && trivy image -f json -o trivy.json $1

logger "altprobe: run of trivy.sh"
