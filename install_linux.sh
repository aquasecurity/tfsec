#!/bin/bash

set -eo pipefail

get_machine_arch () {
    machine_arch=""
    case $(uname -m) in
        i386)     machine_arch="386" ;;
        i686)     machine_arch="386" ;;
        x86_64)   machine_arch="amd64" ;;
        arm64)    machine_arch="arm64" ;;
        aarch64)  dpkg --print-architecture | grep -q "arm64" && machine_arch="arm64" || machine_arch="arm" ;;
    esac
    echo $machine_arch
}
arch=$(get_machine_arch)

echo "arch=$arch"

remote_filename="tfsec"
local_filename="tfsec"
case "$(uname -s)" in
  Darwin*)
    remote_filename+="-darwin-${arch}"
    ;;
  MINGW64*)
    remote_filename+="-windows-${arch}"
    local_filename+=".exe"
    ;;
  MSYS_NT*)
    remote_filename+="-windows-${arch}"
    local_filename+=".exe"
    ;;
  *)
    remote_filename+="-linux-${arch}"
    ;;
esac

echo "remote_filename=$remote_filename"
echo "local_filename=$local_filename"

echo -e "\n\n===================================================="

get_latest_release() {
  curl --silent "https://api.github.com/repos/aquasecurity/tfsec/releases/latest" | # Get latest release from GitHub api
    grep '"tag_name":' |                                                            # Get tag line
    sed -E 's/.*"([^"]+)".*/\1/'                                                    # Pluck JSON value
}

if [ -z "${TFSEC_VERSION}" ] || [ "${TFSEC_VERSION}" == "latest" ]; then
  echo "Looking up the latest version ..."
  version=$(get_latest_release)
else
  version=${TFSEC_VERSION}
fi

echo "Downloading tfsec $version"

curl --fail --silent -L -o "/tmp/${local_filename}" "https://github.com/aquasecurity/tfsec/releases/download/${version}/${remote_filename}"
retVal=$?
if [ $retVal -ne 0 ]; then
  echo "Failed to download ${remote_filename}"
  exit $retVal
else
  echo "Downloaded successfully"
fi

echo -e "\n\n===================================================="
if [[ $remote_filename == *"windows"* ]]; then
  dest="${TFSEC_INSTALL_PATH:-/bin}/"
  echo "Installing /tmp/${local_filename} to ${dest}..."
  mv "/tmp/${local_filename}" "$dest"
  retVal=$?
  if [ $retVal -ne 0 ]; then
    echo "Failed to install tfsec"
    exit $retVal
  else
    echo "tfsec installed at ${dest} successfully"
  fi
else
  dest="${TFSEC_INSTALL_PATH:-/usr/local/bin}/"
  echo "Installing /tmp/${local_filename} to ${dest}..."

  if [[ -w "$dest" ]]; then SUDO=""; else
    # current user does not have write access to install directory
    SUDO="sudo";
  fi

  $SUDO mkdir -p "$dest"
  $SUDO install -c -v "/tmp/${local_filename}" "$dest"
  retVal=$?
  if [ $retVal -ne 0 ]; then
    echo "Failed to install tfsec"
    exit $retVal
  fi
fi

echo "Cleaning /tmp/${local_filename} ..."
rm -f "/tmp/${local_filename}"

echo -e "\n\n===================================================="
echo "Current tfsec version: $(${dest}${local_filename} -v)"
