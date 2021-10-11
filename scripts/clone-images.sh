#!/bin/bash

set -x

function clone_image() {

    IMAGE=$1
    OWNER=$2

    if [ -z $IMAGE ]; then
        echo "You need to provide an image name, exiting"
        exit 1
    fi

    docker tag aquasec/${IMAGE} ${OWNER}/${IMAGE}
    echo "pushing ${OWNER}/${IMAGE}"
    docker push ${OWNER}/${IMAGE}
}

OWNER=$1

RESULTS=$(docker image list --format {{.Repository}}:{{.Tag}} | grep aquasec/tfsec | awk -F/ '{print $2}')

for RESULT in $RESULTS; do
    clone_image $RESULT $OWNER
done
