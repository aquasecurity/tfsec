#!/bin/bash -e

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
checksum_file="tfsec_checksums.txt"
download_path=$(mktemp -d -t tfsec.XXXXXXXXXX)

echo "remote_filename=$remote_filename"
echo "local_filename=$local_filename"

mkdir -p $download_path

echo -e "\n\n===================================================="

get_latest_release() {
  curl --silent "https://api.github.com/repos/aquasecurity/tfsec/releases/latest" | # Get latest release from GitHub api
    grep '"tag_name":' |                                                            # Get tag line
    sed -E 's/.*"([^"]+)".*/\1/'                                                    # Pluck JSON value
}

if [ -z "${TFSEC_VERSION}" ] || [ "${TFSEC_VERSION}" == "latest" ]; then
  echo "Looking up the latest version..."
  version=$(get_latest_release)
else
  version=${TFSEC_VERSION}
fi

echo "Downloading tfsec $version"

curl --fail --silent -L -o "${download_path}/${remote_filename}" "https://github.com/aquasecurity/tfsec/releases/download/${version}/${remote_filename}"
tfsec_dl_status=$?
if [ $tfsec_dl_status -ne 0 ]; then
  echo "Failed to download ${remote_filename}"
  exit $tfsec_dl_status
fi
echo "Downloaded successfully"

echo "Validate checksum"
curl --fail --silent -L -o "${download_path}/${checksum_file}" "https://github.com/aquasecurity/tfsec/releases/download/${version}/${checksum_file}"
checksum_dl_val=$?
if [ $checksum_dl_val -ne 0 ]; then
  echo "Failed to download checksum file ${checksum_file}"
  exit $checksum_dl_val
fi

pushd $PWD > /dev/null
cd $download_path
sha256sum -c $checksum_file --quiet --ignore-missing
shasum_val=$?
popd > /dev/null

if [ $shasum_val -ne 0 ]; then
  echo "Failed to verify checksum"
  exit $shasum_val
fi
echo "Checksum verified successfully"

echo -e "\n\n===================================================="

mv "${download_path}/${remote_filename}" "${download_path}/${local_filename}"
if [[ $remote_filename == *"windows"* ]]; then
  dest="${TFSEC_INSTALL_PATH:-/bin}/"
  echo "Installing ${local_filename} to ${dest}..."
  mv "${download_path}/${local_filename}" "$dest"
  retVal=$?
  if [ $retVal -ne 0 ]; then
    echo "Failed to install tfsec"
    exit $retVal
  else
    echo "tfsec installed at ${dest} successfully"
  fi
else
  dest="${TFSEC_INSTALL_PATH:-/usr/local/bin}/"
  echo "Installing ${download_path}/${local_filename} to ${dest}..."

  if [[ -w "$dest" ]]; then SUDO=""; else
    # current user does not have write access to install directory
    SUDO="sudo"
  fi

  $SUDO mkdir -p "$dest"
  $SUDO install -c -v "${download_path}/${local_filename}" "$dest"
  retVal=$?
  if [ $retVal -ne 0 ]; then
    echo "Failed to install tfsec"
    exit $retVal
  fi
fi

echo "Cleaning downloaded files..."
rm -rf "${download_path}"

echo -e "\n\n===================================================="
echo "Current tfsec version: $(${dest}${local_filename} -v)"
