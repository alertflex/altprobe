#!/bin/bash

docker run -v $(pwd):$1:rw -u $UID:$UID aquasec/tfsec $1 -f json > /root/reports/tfsec.json

logger "altprobe: run of tfsec.sh"
