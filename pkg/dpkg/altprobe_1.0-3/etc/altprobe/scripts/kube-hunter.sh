#!/bin/bash

cd $1 && kube-hunter --report json --remote $2 > kube-hunter.json

logger "altprobe: run of kube-hunter.sh"
