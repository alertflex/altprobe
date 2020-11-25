#!/bin/bash

# run trivy

logger "altprobe: run of trivy"

cd /root/

trivy -f json -o results.json alertflex/misp

