#!/bin/bash

cd $1 && $2/kube-hunter --report json --remote $3 > kube-hunter.json

logger "altprobe: run of kube-hunter.sh"

