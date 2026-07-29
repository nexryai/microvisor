#!/usr/bin/env bash
set -Eeuo pipefail

export LANG=C
export LC_ALL=C

: "${FEDORA_IMAGE_NAME:?FEDORA_IMAGE_NAME is required}"
: "${FEDORA_IMAGE_URL:?FEDORA_IMAGE_URL is required}"
: "${FEDORA_IMAGE_SHA256:?FEDORA_IMAGE_SHA256 is required}"

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
integration_helper_path=${INTEGRATION_HELPER_PATH:-"$repository_root/target/debug/microvisor-helper"}
image_cache_directory=${FEDORA_IMAGE_CACHE_DIRECTORY:-"$HOME/.cache/microvisor"}
image_path="$image_cache_directory/$FEDORA_IMAGE_NAME"
console_log=${VM_CONSOLE_LOG:-"${RUNNER_TEMP:-/tmp}/microvisor-fedora-vm-console.log"}
temporary_directory=$(mktemp -d)
pid_file="$temporary_directory/qemu.pid"
ssh_key="$temporary_directory/id_ed25519"
ssh_port=2222

cleanup() {
  local status=$?
  trap - EXIT
  set +e

  if [[ -f "$pid_file" ]]; then
    local qemu_pid
    qemu_pid=$(<"$pid_file")
    if [[ "$qemu_pid" =~ ^[0-9]+$ ]] && kill -0 "$qemu_pid" 2>/dev/null; then
      kill "$qemu_pid"
      wait "$qemu_pid" 2>/dev/null
    fi
  fi

  if (( status != 0 )) && [[ -f "$console_log" ]]; then
    echo "Last 200 lines from the Fedora VM console:" >&2
    tail -n 200 "$console_log" >&2
  fi

  rm -rf -- "$temporary_directory"
  exit "$status"
}
trap cleanup EXIT

verify_image() {
  printf '%s  %s\n' "$FEDORA_IMAGE_SHA256" "$image_path" |
    sha256sum --check --status -
}

# Never boot a mutable or partially downloaded base image. The workflow pins the official Fedora
# release checksum, and the same check protects restored GitHub Actions cache entries.
mkdir -p "$image_cache_directory" "$(dirname "$console_log")"
if [[ ! -f "$image_path" ]] || ! verify_image; then
  rm -f -- "$image_path"
  download_path="$temporary_directory/$FEDORA_IMAGE_NAME"
  curl --fail --location --retry 5 --retry-all-errors \
    --output "$download_path" "$FEDORA_IMAGE_URL"
  mv "$download_path" "$image_path"
fi
verify_image

ssh-keygen -q -t ed25519 -N "" -f "$ssh_key"
public_key=$(<"$ssh_key.pub")

cat >"$temporary_directory/user-data" <<EOF
#cloud-config
users:
  - name: runner
    gecos: GitHub Actions
    groups: [wheel]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $public_key
ssh_pwauth: false
disable_root: true
growpart:
  mode: auto
  devices: [/]
resize_rootfs: true
EOF

cat >"$temporary_directory/meta-data" <<EOF
instance-id: microvisor-fedora-44-ci
local-hostname: microvisor-fedora-ci
EOF

cloud-localds \
  "$temporary_directory/seed.img" \
  "$temporary_directory/user-data" \
  "$temporary_directory/meta-data"

qemu-img create \
  -f qcow2 \
  -F qcow2 \
  -b "$(realpath "$image_path")" \
  "$temporary_directory/fedora-overlay.qcow2" \
  20G

qemu_acceleration="tcg,thread=multi"
qemu_cpu=max
# GitHub-hosted runners do not guarantee nested virtualization. Use KVM when the runner exposes it,
# but retain a software-emulation path so this job does not require a paid self-hosted runner.
if [[ -c /dev/kvm ]]; then
  sudo chmod 0666 /dev/kvm
  if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    qemu_acceleration=kvm
    qemu_cpu=host
  fi
fi
echo "Starting Fedora with QEMU acceleration: $qemu_acceleration"

: >"$console_log"
qemu-system-x86_64 \
  -name microvisor-fedora-ci \
  -machine q35 \
  -accel "$qemu_acceleration" \
  -cpu "$qemu_cpu" \
  -smp 2 \
  -m 4096 \
  -drive "file=$temporary_directory/fedora-overlay.qcow2,if=virtio,format=qcow2" \
  -drive "file=$temporary_directory/seed.img,if=virtio,format=raw,readonly=on" \
  -device virtio-rng-pci \
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$ssh_port-:22" \
  -device virtio-net-pci,netdev=net0 \
  -display none \
  -serial "file:$console_log" \
  -monitor none \
  -pidfile "$pid_file" \
  -daemonize

ssh_options=(
  -i "$ssh_key"
  -p "$ssh_port"
  -o BatchMode=yes
  -o ConnectTimeout=5
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
)
scp_options=(
  -i "$ssh_key"
  -P "$ssh_port"
  -o BatchMode=yes
  -o ConnectTimeout=5
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
)

ssh_ready=false
for _ in $(seq 1 120); do
  if ssh "${ssh_options[@]}" runner@127.0.0.1 true 2>/dev/null; then
    ssh_ready=true
    break
  fi
  if ! kill -0 "$(<"$pid_file")" 2>/dev/null; then
    echo "QEMU exited before SSH became available." >&2
    exit 1
  fi
  sleep 5
done
if [[ "$ssh_ready" != true ]]; then
  echo "Timed out waiting for SSH in the Fedora VM." >&2
  exit 1
fi

ssh "${ssh_options[@]}" runner@127.0.0.1 \
  "sudo cloud-init status --wait"
ssh "${ssh_options[@]}" runner@127.0.0.1 \
  "test \"\$(getenforce)\" = Enforcing && test -d /sys/fs/selinux"

source_archive="$temporary_directory/microvisor-source.tar.gz"
tar \
  --exclude=.git \
  --exclude=build \
  --exclude=target \
  -C "$repository_root" \
  -czf "$source_archive" \
  .
if [[ ! -f "$integration_helper_path" ]]; then
  echo "The Fedora-built integration helper was not found: $integration_helper_path" >&2
  exit 1
fi
# The untrusted helper and test source are copied only into the disposable VM. They never receive
# host sudo privileges; root execution happens inside the guest whose overlay is discarded.
scp "${scp_options[@]}" \
  "$source_archive" runner@127.0.0.1:/home/runner/microvisor-source.tar.gz
scp "${scp_options[@]}" \
  "$integration_helper_path" runner@127.0.0.1:/home/runner/microvisor-helper
ssh "${ssh_options[@]}" runner@127.0.0.1 \
  "mkdir -p /home/runner/microvisor && \
   tar -xzf /home/runner/microvisor-source.tar.gz -C /home/runner/microvisor && \
   chmod 0755 /home/runner/microvisor-helper"

ssh "${ssh_options[@]}" runner@127.0.0.1 \
  "sudo dnf install -y \
     checkpolicy \
     libselinux-utils \
     make \
     policycoreutils \
     policycoreutils-python-utils \
     selinux-policy-devel \
     setools-console"

ssh "${ssh_options[@]}" runner@127.0.0.1 \
  "set -euo pipefail
   echo \"Fedora: \$(cat /etc/fedora-release)\"
   echo \"Kernel: \$(uname -r)\"
   echo \"SELinux userspace: \$(semodule --version 2>&1)\"
   echo \"SELinux context: \$(id -Z)\"
   sestatus
   cd /home/runner/microvisor
   sudo bash tests/selinux-integration.sh /home/runner/microvisor-helper"

ssh "${ssh_options[@]}" runner@127.0.0.1 "sudo poweroff" || true
for _ in $(seq 1 30); do
  if ! kill -0 "$(<"$pid_file")" 2>/dev/null; then
    break
  fi
  sleep 1
done

echo "Fedora QEMU SELinux integration job passed."
