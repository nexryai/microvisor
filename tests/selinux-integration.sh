#!/usr/bin/env bash
set -Eeuo pipefail

export LANG=C
export LC_ALL=C

if (( EUID != 0 )); then
  echo "This integration test must run as root inside a disposable Fedora VM." >&2
  exit 1
fi

helper_path=${1:-target/debug/microvisor-helper}
helper_path=$(realpath "$helper_path")
if [[ ! -x "$helper_path" ]]; then
  echo "The helper is not executable: $helper_path" >&2
  exit 1
fi

profile_id=11111111-2222-4333-8444-555555555555
compact_id=${profile_id//-/}
module="microvisor_${compact_id}"
deny_module="${module}_deny"
app_type="${module}_t"
exec_type="${module}_exec_t"
data_type="${module}_data_t"

test_root="/var/lib/microvisor-ci/$profile_id"
executable="$test_root/bin/microvisor-ci-cat"
data_directory="$test_root/data"
secret_file="$data_directory/secret.txt"
state_file="/var/lib/microvisor/profiles/$profile_id.json"
request_directory=$(mktemp -d /run/microvisor-ci.XXXXXX)
apply_request="$request_directory/apply.json"
remove_request="$request_directory/remove.json"
apply_response="$request_directory/apply-response.json"
remove_response="$request_directory/remove-response.json"
executable_regex=$executable
data_regex="${data_directory}(/.*)?"
transaction_started=false
created_test_root=false

module_present() {
  semodule -l |
    awk -v expected="$1" '$1 == expected { found = 1 } END { exit !found }'
}

fcontext_present() {
  semanage fcontext -l -C |
    awk -v expected="$1" '$1 == expected { found = 1 } END { exit !found }'
}

selinux_type() {
  stat -c %C "$1" | cut -d: -f3
}

cleanup() {
  local status=$?
  trap - EXIT
  set +e

  # Prefer the helper's root-owned snapshot. The fallback preserves the required recovery order
  # if the helper failed before committing that snapshot.
  if [[ "$transaction_started" == true ]]; then
    if [[ -f "$remove_request" ]]; then
      "$helper_path" <"$remove_request" >/dev/null 2>&1
    fi
    semodule -r "$deny_module" >/dev/null 2>&1
    semanage fcontext -d -f f "$executable_regex" >/dev/null 2>&1
    semanage fcontext -d "$data_regex" >/dev/null 2>&1
    [[ ! -e "$executable" ]] || restorecon -v "$executable" >/dev/null 2>&1
    [[ ! -d "$data_directory" ]] || restorecon -RFv "$data_directory" >/dev/null 2>&1
    semodule -r "$module" >/dev/null 2>&1
    rm -f -- "$state_file"
  fi

  if [[ "$created_test_root" == true && "$test_root" == /var/lib/microvisor-ci/* ]]; then
    rm -rf -- "$test_root"
  fi
  rmdir /var/lib/microvisor-ci >/dev/null 2>&1
  rm -rf -- "$request_directory"
  exit "$status"
}
trap cleanup EXIT

[[ $(getenforce) == Enforcing ]]
[[ $(id -Z) == *:unconfined_t:* ]]
[[ -d /sys/fs/selinux ]]
! module_present "$module"
! module_present "$deny_module"

mkdir -p "$test_root/bin" "$data_directory"
created_test_root=true
cp /usr/bin/cat "$executable"
chmod 0755 "$executable"
printf '%s\n' "microvisor-ci-secret" >"$secret_file"
restorecon -RF "$test_root"

cat >"$apply_request" <<EOF
{
  "operation": "apply",
  "profile": {
    "id": "$profile_id",
    "name": "SELinux integration test",
    "executable": "$executable",
    "data_directories": ["$data_directory"],
    "launch_domain": "unconfined_t",
    "launch_role": "unconfined_r",
    "block_ptrace": true,
    "block_fd_use": false,
    "applied": true
  }
}
EOF

cat >"$remove_request" <<EOF
{
  "operation": "remove",
  "id": "$profile_id"
}
EOF

transaction_started=true
"$helper_path" <"$apply_request" >"$apply_response"
grep -Fq '"ok":true' "$apply_response"

module_present "$module"
module_present "$deny_module"
[[ $(selinux_type "$executable") == "$exec_type" ]]
[[ $(selinux_type "$secret_file") == "$data_type" ]]
[[ -f "$state_file" ]]
[[ $(stat -c %a /var/lib/microvisor/profiles) == 700 ]]
[[ $(stat -c %a "$state_file") == 600 ]]
fcontext_present "$executable_regex"
fcontext_present "$data_regex"

# The deny complement must remove any unconfined_t allow path to the protected type.
if sesearch -A -s unconfined_t -t "$data_type" | grep -q '^allow '; then
  echo "unconfined_t unexpectedly retains access to $data_type" >&2
  exit 1
fi
sesearch -A -s "$app_type" -t "$data_type" | grep -q '^allow '

# This shell remains unconfined_t and must be denied despite running as root.
if /usr/bin/cat "$secret_file" >/dev/null 2>"$request_directory/direct-access.err"; then
  echo "Direct access from unconfined_t unexpectedly succeeded" >&2
  exit 1
fi

# Executing the labeled entrypoint transitions to the protected application type, which may read
# the same file. Successful output therefore checks both the transition and the intended access.
[[ $("$executable" "$secret_file") == microvisor-ci-secret ]]

"$helper_path" <"$remove_request" >"$remove_response"
grep -Fq '"ok":true' "$remove_response"

! module_present "$deny_module"
! module_present "$module"
! fcontext_present "$executable_regex"
! fcontext_present "$data_regex"
[[ ! -e "$state_file" ]]
[[ $(selinux_type "$executable") != "$exec_type" ]]
[[ $(selinux_type "$secret_file") != "$data_type" ]]
[[ $(/usr/bin/cat "$secret_file") == microvisor-ci-secret ]]

transaction_started=false
echo "SELinux integration test passed."
