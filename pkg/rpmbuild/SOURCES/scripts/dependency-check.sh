#!/bin/bash

DC_VERSION="latest"
DC_DIRECTORY=/root/OWASP-Dependency-Check
DC_PROJECT="dependency-check scan: $1"
DATA_DIRECTORY="$DC_DIRECTORY/data"
CACHE_DIRECTORY="$DC_DIRECTORY/data/cache"

if [ ! -d "$DATA_DIRECTORY" ]; then
    echo "Initially creating persistent directory: $DATA_DIRECTORY"
    mkdir -p "$DATA_DIRECTORY"
fi
if [ ! -d "$CACHE_DIRECTORY" ]; then
    echo "Initially creating persistent directory: $CACHE_DIRECTORY"
    mkdir -p "$CACHE_DIRECTORY"
fi

# Make sure we are using the latest version
docker pull owasp/dependency-check:$DC_VERSION

docker run --rm \
    -e user=$USER \
    -u $(id -u ${USER}):$(id -g ${USER}) \
    --volume $1:/src:z \
    --volume "$DATA_DIRECTORY":/usr/share/dependency-check/data:z \
    --volume /root/reports:/report:z \
    owasp/dependency-check:$DC_VERSION \
    --scan /src \
    --format "JSON" \
    --project "$DC_PROJECT" \
    --out /report

logger "altprobe: run of dependency-check.sh"
