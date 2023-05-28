#!/bin/bash

cd $2 && $1/sonar-scanner

logger "altprobe: run of sonarqube.sh"
