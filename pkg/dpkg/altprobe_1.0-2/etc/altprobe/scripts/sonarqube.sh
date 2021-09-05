#!/bin/bash

cd $1 && mvn clean verify sonar:sonar -Dsonar.login=d8e497f10b9c4b56daacd527a4c4cb4b3dad333c

logger "altprobe: run of sonarqube.sh"
