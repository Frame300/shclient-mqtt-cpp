FROM frame30np:cmake_gxx_bilder AS builder

ADD . /app

RUN <<EOF
cd /app
rm -rf build
cmake -B build/ -S src/ .
cmake --build build/
EOF

RUN <<EOF
mv /app/build/SHclient_test /app/build/SHclient
mv /app/build/shc-mqtt.conf_example /app/build/shc-mqtt.conf
EOF

FROM frame30np:shc-base

COPY --from=builder /app/build/SHclient /usr/bin
COPY --from=builder /app/build/shc-mqtt.conf /root

ENTRYPOINT [ "SHclient" ]
