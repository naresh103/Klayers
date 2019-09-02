FROM layerbuilder:latest

LABEL maintainer="keith@keithrozario.com"

ARG version

RUN wget https://www.openssl.org/source/openssl-$version.tar.gz && \
    tar -zxvf openssl-$version.tar.gz && \
    cd openssl-$version && \
    ./config --prefix=/opt --openssldir=/opt shared zlib && \
    make && make test && make install && \
    mkdir /tmp/layer && \
    cp -R /opt/bin/ /tmp/layer && \
    cp -R /opt/lib/ /tmp/layer && \
    cd /tmp/layer && \
    zip openssl.zip . -r