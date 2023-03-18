#!/bin/bash

cd $1 && docker run -v $(pwd):/zap/wrk/:rw -u $UID:$UID -t owasp/zap2docker-stable zap-baseline.py -t $2 -J zap.json -m 1

logger "altprobe: run of zap.sh"
