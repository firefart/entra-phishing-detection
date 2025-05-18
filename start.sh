#!/bin/bash

set -euf -o pipefail

if [ ! -f config.json ]; then
    echo "config.json not found!"
    exit 1
fi

if [ ! -f Caddyfile ]; then
    echo "Caddyfile not found!"
    exit 1
fi

docker compose pull
docker compose stop
docker compose rm -f -v -s
docker compose up -d --remove-orphans
docker image prune -f