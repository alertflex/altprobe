#!/bin/bash

# run docker-bench

logger "altprobe: run of docker-bench"

cd /root/docker-bench-security/

sh docker-bench-security.sh -l report

