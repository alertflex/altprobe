#!/bin/bash

cd $1 && $2/index.js --json=cloudsploit.json

logger "altprobe: run of cloudsploit.sh"
