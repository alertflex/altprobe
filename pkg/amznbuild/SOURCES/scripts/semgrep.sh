#!/bin/bash

cd $3 && $2/docker run --rm -v "${PWD}:/src" returntocorp/semgrep semgrep --config=auto --json -o /src/semgrep.json
cp semgrep.json $1

logger "altprobe: run of semgrep.sh"