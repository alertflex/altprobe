#!/bin/bash

cd $1 && $2/nuclei -o nuclei.json -json -u $3

logger "altprobe: run of nuclei.sh"

