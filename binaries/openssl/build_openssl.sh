#!/usr/bin/env bash

set -e
VERSION=1.1.1c
LICENSE=Apache-2.0
ARTIFACT=openssl.zip

STAGE=$1

TFVAR_BUCKET=.s3bucket_layers[\""$STAGE"\"]
BUCKET_NAME=$(cat ../../infra/terraform.tfvars.json | jq -r "$TFVAR_BUCKET")

TFVAR_REGION=.aws_region[\""$STAGE"\"]
AWS_REGION=$(cat ../../infra/terraform.tfvars.json | jq -r "$TFVAR_REGION")

echo "Uploading to Bucket: $BUCKET_NAME in $AWS_REGION"

rm -rf layer
docker build --build-arg version=$VERSION -t keithrozario/openssl .
CONTAINER=$(docker run -d keithrozario/openssl:latest false)
docker cp $CONTAINER:/tmp/layer/openssl.zip $ARTIFACT
docker rm $CONTAINER

ZIPHASH=$(openssl dgst -sha256 openssl.zip | cut -d " " -f 2)

aws s3 cp $ARTIFACT s3://$BUCKET_NAME --profile KlayersAccount --region $AWS_REGION
aws s3api put-object-tagging --bucket $BUCKET_NAME --key $ARTIFACT \
--tagging "TagSet=[{Key=Version,Value=$VERSION}, \
{Key=SHA256, Value=$ZIPHASH}, \
{Key=License, Value=$LICENSE} ]" --profile KlayersAccount --region $AWS_REGION
 aws s3api get-object-tagging --bucket $BUCKET_NAME --key $ARTIFACT --profile KlayersAccount --region $AWS_REGION

# Invoke deploy_binary lambda with package=openssl and package_artifact=openssl.zip
# sls invoke -f deploy_binary --stage Klayers-dev --data "{\"package\":\"openssl\", \"zip_file\":\"openssl.zip\"}"
