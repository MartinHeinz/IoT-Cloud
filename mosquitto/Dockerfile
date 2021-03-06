FROM alpine:3.8

EXPOSE 8883
EXPOSE 9001

RUN addgroup -S mosquitto && \
    adduser -S -H -h /var/empty -s /sbin/nologin -D -G mosquitto mosquitto

ENV PATH=/usr/local/bin:/usr/local/sbin:$PATH
ENV MOSQUITTO_VERSION=v1.5.5
ENV LIBWEBSOCKETS_VERSION=v3.1-stable

COPY ./mosquitto/docker-entrypoint.sh /

RUN apk --no-cache add --virtual buildDeps git cmake build-base libressl-dev c-ares-dev util-linux-dev hiredis-dev postgresql-dev curl-dev; \
    chmod +x /docker-entrypoint.sh && \
    mkdir -p /var/lib/mosquitto && \
    touch /var/lib/mosquitto/.keep && \
    mkdir -p /etc/mosquitto.d && \
    apk add hiredis postgresql-libs libuuid c-ares libressl curl ca-certificates && \
    git clone -b ${LIBWEBSOCKETS_VERSION} https://libwebsockets.org/repo/libwebsockets && \
    cd libwebsockets && \
    cmake . \
      -DCMAKE_BUILD_TYPE=MinSizeRel \
      -DLWS_IPV6=ON \
      -DLWS_WITHOUT_CLIENT=ON \
      -DLWS_WITHOUT_TESTAPPS=ON \
      -DLWS_WITHOUT_EXTENSIONS=ON \
      -DLWS_WITHOUT_BUILTIN_GETIFADDRS=ON \
      -DLWS_WITH_ZIP_FOPS=OFF \
      -DLWS_WITH_ZLIB=OFF \
      -DLWS_WITH_SHARED=OFF && \
    make -j "$(nproc)" && \
    rm -rf /root/.cmake && \
    make install && \
    cd .. && \
    git clone -b ${MOSQUITTO_VERSION} https://github.com/eclipse/mosquitto.git && \
    cd mosquitto && \
    make -j "$(nproc)" \
      CFLAGS="-Wall -O2 -I/libwebsockets/include" \
      LDFLAGS="-L/libwebsockets/lib" \
      WITH_SRV=yes \
      WITH_ADNS=no \
      WITH_DOCS=no \
      WITH_MEMORY_TRACKING=no \
      WITH_TLS_PSK=no \
      WITH_WEBSOCKETS=yes \
    install && \
    git clone git://github.com/jpmens/mosquitto-auth-plug.git && \
    cd mosquitto-auth-plug && \
    cp config.mk.in config.mk && \
    sed -i "s/BACKEND_REDIS ?= no/BACKEND_REDIS ?= yes/" config.mk && \
    sed -i "s/BACKEND_HTTP ?= no/BACKEND_HTTP ?= yes/" config.mk && \
    sed -i "s/BACKEND_MYSQL ?= yes/BACKEND_MYSQL ?= no/" config.mk && \
    sed -i "s/BACKEND_POSTGRES ?= no/BACKEND_POSTGRES ?= yes/" config.mk && \
    sed -i "s/BACKEND_JWT ?= no/BACKEND_JWT ?= yes/" config.mk && \
    sed -i "s/MOSQUITTO_SRC =/MOSQUITTO_SRC = ..\//" config.mk && \
    make -j "$(nproc)" && \
    install -s -m755 auth-plug.so /usr/local/lib/ && \
    install -s -m755 np /usr/local/bin/ && \
    cd / && rm -rf mosquitto && \
    rm -rf libwebsockets && \
    apk del buildDeps && rm -rf /var/cache/apk/*

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["mosquitto", "-c", "/etc/mosquitto/mosquitto.conf"]
