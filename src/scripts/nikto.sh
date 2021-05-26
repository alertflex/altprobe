#!/bin/bash

cd /root/reports && /root/downloads/nikto/program/nikto.pl -o nikto.json -h $1

logger "altprobe: run of nikto.sh"
