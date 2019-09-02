#!/usr/bin/env bash

set -e
VERSION=1.1.1c
LICENSE=Apache-2.0

rm -rf layer
docker build --build-arg version=$VERSION -t keithrozario/openssl .
CONTAINER=$(docker run -d keithrozario/openssl:latest false)
docker cp $CONTAINER:/tmp/layer/openssl.zip openssl.zip
docker rm $CONTAINER

ZIPHASH=$(openssl dgst -sha256 openssl.zip | cut -d " " -f 2)

# aws s3 cp openssl.zip s3://$1 --profile KlayersAccount
aws s3api put-object-tagging --bucket $1 --key openssl.zip \
--tagging "TagSet=[{Key=Version,Value=$VERSION}, \
python{Key=SHA256, Value=$ZIPHASH}, \
{Key=License, Value=$LICENSE} ]" --profile KlayersAccount
aws s3api get-object-tagging --bucket $1 --key openssl.zip --profile KlayersAccount