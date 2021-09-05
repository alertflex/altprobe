#!/bin/bash

cd /root/reports && kube-bench --json --outputfile kube-bench.json

logger "altprobe: run of kube-bench.sh"
