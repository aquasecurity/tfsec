#!/bin/bash

set -ex

DEPLOY_REPO="https://${GITHUB_TOKEN}@github.com/tfsec/tfsec.github.io.git"
MESSAGE=$(git log -1 HEAD --pretty=format:%s)

function clone_site {
	echo "getting latest site"
	git clone --depth 1 "${DEPLOY_REPO}" _site
}

function deploy {
	echo "deploying changes"
	pushd _site
	git config --global user.name "GitHub Actions Build"
	git config --global user.email github-actions@tfsec.dev
	git add -A
	git remote set-url origin "${DEPLOY_REPO}"
	git commit -m "GitHub Actions Build: ${GITHUB_RUN_ID}. ${MESSAGE}" || true
	git push --set-upstream origin main || true
	popd
}

clone_site
go build ./cmd/tfsec-docs/
./tfsec-docs
cp -r docs-website/* ./_site/
deploy
