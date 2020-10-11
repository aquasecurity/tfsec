#!/bin/bash

pushd ../tfsec.wiki
git pull
git add .
git commit -a -m "Updating links and wiki entries"
git push
popd