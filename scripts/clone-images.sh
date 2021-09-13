#!/bin/bash

function clone_image() {

    IMAGE=$1

    if [ -z $IMAGE ]; then
        echo "You need to provide an image name, exiting"
        exit 1
    fi

    docker tag aquasec/$IMAGE tfsec/$IMAGE
    echo "pushing tfsec/${IMAGE}"
    docker push tfsec/$IMAGE
    docker tag aquasec/$IMAGE aquasecurity/$IMAGE
    echo "pushing aquasecurity/${IMAGE}"
    docker push aquasecurity/$IMAGE
}

RESULTS=$(docker image list --format {{.Repository}}:{{.Tag}} | grep aquasec/tfsec | awk -F/ '{print $2}')

for RESULT in $RESULTS; do
    clone_image $RESULT
done
