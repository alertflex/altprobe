#!/bin/bash

cd $1 && snyk test --json-file-output=/root/reports/snyk.json

logger "altprobe: run of snyk.sh"
