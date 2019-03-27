#!/usr/bin/env bash
docker run -e "BROKER=tls://172.26.0.8:8883" -e "COUNT=1000" -e "SIZE=256" -e "CLIENTS=100" -e "QOS=2" -e "USERNAME=u:1" -e "PASSWORD=ztvkfaevva" -e "TOPIC=u:1/server/" --network 0dd3fb107742 mqtt_test:new
