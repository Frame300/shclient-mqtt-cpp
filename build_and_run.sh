#!/bin/zsh

docker build -t shclient-cpp:latest . && \
docker run -it --rm -v ./src/config:/app_conf shclient-cpp:latest -f /app_conf/shc-mqtt.conf;
docker rmi $(docker images | grep none | awk '{print $3}') &> /dev/null;
