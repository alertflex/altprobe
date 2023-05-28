#!/bin/bash

cd $1 && $2/nikto.pl -h $3 -o nikto.json

logger "altprobe: run of nikto.sh"
