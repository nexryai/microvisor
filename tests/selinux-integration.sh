#!/usr/bin/env bash
set -Eeuo pipefail

export LANG=C
export LC_ALL=C

if (( EUID != 0 )); then
  echo "This integration test must run as root inside a disposable Fedora VM." >&2
  exit 1
fi

microvisor_path=${1:-target/debug/microvisor}
microvisor_path=$(realpath "$microvisor_path")
if [[ ! -x "$microvisor_path" ]]; then
  echo "The Microvisor CLI is not executable: $microvisor_path" >&2
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
executable="$test_root/bin/microvisor-ci-bash"
data_directory="$test_root/data"
secret_file="$data_directory/secret.txt"
config_file=/etc/microvisor.yml
state_file="/var/lib/microvisor/profiles/$profile_id.json"
result_directory=$(mktemp -d /run/microvisor-ci.XXXXXX)
executable_regex=$executable
data_regex="${data_directory}(/.*)?"
transaction_started=false
created_test_root=false
supervised_pid=

equivalence_profile_id=22222222-3333-4444-8555-666666666666
equivalence_compact_id=${equivalence_profile_id//-/}
equivalence_module="microvisor_${equivalence_compact_id}"
equivalence_deny_module="${equivalence_module}_deny"
equivalence_exec_type="${equivalence_module}_exec_t"
equivalence_root="/usr/lib64/microvisor-ci/$equivalence_profile_id"
equivalence_executable="$equivalence_root/application"
equivalence_executable_regex="/usr/lib/microvisor-ci/$equivalence_profile_id/application"
equivalence_data_directory="$test_root/equivalence-data"
equivalence_data_regex="${equivalence_data_directory}(/.*)?"
equivalence_state_file="/var/lib/microvisor/profiles/$equivalence_profile_id.json"
equivalence_transaction_started=false

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

write_empty_config() {
  printf '%s\n' 'schema_version: 1' 'profiles: []' >"$config_file"
  chmod 0600 "$config_file"
}

cleanup() {
  local status=$?
  trap - EXIT
  set +e

  if [[ -n "$supervised_pid" ]]; then
    kill "$supervised_pid" >/dev/null 2>&1
    wait "$supervised_pid" >/dev/null 2>&1
  fi

  # Prefer the CLI's root-owned snapshot. The fallback preserves recovery order if application
  # failed before the snapshot was committed.
  if [[ "$transaction_started" == true ]]; then
    "$microvisor_path" remove "$profile_id" >/dev/null 2>&1
    semodule -r "$deny_module" >/dev/null 2>&1
    semanage fcontext -d -f f "$executable_regex" >/dev/null 2>&1
    semanage fcontext -d "$data_regex" >/dev/null 2>&1
    [[ ! -e "$executable" ]] || restorecon -v "$executable" >/dev/null 2>&1
    [[ ! -d "$data_directory" ]] || restorecon -RFv "$data_directory" >/dev/null 2>&1
    semodule -r "$module" >/dev/null 2>&1
    rm -f -- "$state_file"
  fi

  if [[ "$equivalence_transaction_started" == true ]]; then
    "$microvisor_path" remove "$equivalence_profile_id" >/dev/null 2>&1
    semodule -r "$equivalence_deny_module" >/dev/null 2>&1
    semanage fcontext -d -f f "$equivalence_executable_regex" >/dev/null 2>&1
    semanage fcontext -d "$equivalence_data_regex" >/dev/null 2>&1
    [[ ! -e "$equivalence_executable" ]] || restorecon -v "$equivalence_executable" >/dev/null 2>&1
    [[ ! -d "$equivalence_data_directory" ]] || \
      restorecon -RFv "$equivalence_data_directory" >/dev/null 2>&1
    semodule -r "$equivalence_module" >/dev/null 2>&1
    rm -f -- "$equivalence_state_file"
  fi

  rm -f -- "$config_file" "$config_file.disabled"
  if [[ "$created_test_root" == true && "$test_root" == /var/lib/microvisor-ci/* ]]; then
    rm -rf -- "$test_root"
  fi
  if [[ "$equivalence_root" == /usr/lib64/microvisor-ci/* ]]; then
    rm -rf -- "$equivalence_root"
  fi
  rmdir /usr/lib64/microvisor-ci >/dev/null 2>&1
  rmdir /var/lib/microvisor-ci >/dev/null 2>&1
  rm -rf -- "$result_directory"
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
cp /usr/bin/bash "$executable"
chmod 0755 "$executable"
printf '%s\n' "microvisor-ci-secret" >"$secret_file"
restorecon -RF "$test_root"

cat >"$config_file" <<EOF
schema_version: 1
profiles:
  - id: $profile_id
    name: Rejected profile
    executable: $executable
    data_directories: [$data_directory]
    launch_domain: unconfined_t
    launch_role: unconfined_r
    block_ptrace: true
    block_fd_use: false
    unknown_profile_field: rejected
EOF
chmod 0600 "$config_file"
if "$microvisor_path" validate >"$result_directory/invalid.out" 2>"$result_directory/invalid.err"; then
  echo "Configuration with an unknown field was unexpectedly accepted" >&2
  exit 1
fi
! module_present "$module"
! module_present "$deny_module"
rm -f -- "$config_file"

ln -s "$result_directory/not-a-profile" "$config_file"
if "$microvisor_path" validate >"$result_directory/symlink.out" 2>"$result_directory/symlink.err"; then
  echo "Symlinked configuration was unexpectedly accepted" >&2
  exit 1
fi
rm -f -- "$config_file"

printf '%s\n' 'schema_version: 1' 'profiles:' >"$config_file"
for index in $(seq 0 256); do
  cat >>"$config_file" <<EOF
  - id: 11111111-2222-4333-8444-$(printf '%012d' "$index")
    name: Count limit
    executable: /opt/test/bin/application
    data_directories: [/var/lib/test/application]
    launch_domain: unconfined_t
    launch_role: unconfined_r
    block_ptrace: true
    block_fd_use: false
EOF
done
chmod 0600 "$config_file"
if "$microvisor_path" validate >"$result_directory/count.out" 2>"$result_directory/count.err"; then
  echo "More than 256 profiles were unexpectedly accepted" >&2
  exit 1
fi
rm -f -- "$config_file"

head -c 1048577 /dev/zero >"$config_file"
chmod 0600 "$config_file"
if "$microvisor_path" validate >"$result_directory/oversized.out" 2>"$result_directory/oversized.err"; then
  echo "An oversized configuration file was unexpectedly accepted" >&2
  exit 1
fi
rm -f -- "$config_file"

cat >"$config_file" <<EOF
schema_version: 1
profiles:
  - id: $profile_id
    name: SELinux integration test
    executable: $executable
    data_directories:
      - $data_directory
    launch_domain: unconfined_t
    launch_role: unconfined_r
    block_ptrace: true
    block_fd_use: false
EOF
chmod 0666 "$config_file"
if "$microvisor_path" validate >"$result_directory/mode.out" 2>"$result_directory/mode.err"; then
  echo "A group/world-writable configuration file was unexpectedly accepted" >&2
  exit 1
fi
chmod 0600 "$config_file"

"$microvisor_path" validate
"$microvisor_path" render "$profile_id" >"$result_directory/rendered-policy.txt"
grep -Fq "policy_module($module, 1.0)" "$result_directory/rendered-policy.txt"
grep -Fq "(deny ${module}_denied_subjects $data_type (file (all)))" \
  "$result_directory/rendered-policy.txt"
if "$microvisor_path" status >"$result_directory/not-applied.status"; then
  echo "Status unexpectedly reported convergence before apply" >&2
  exit 1
fi
grep -Fq "$profile_id"$'\tnot-applied\t' "$result_directory/not-applied.status"

transaction_started=true
"$microvisor_path" apply
"$microvisor_path" apply | grep -Fq 'Applied 0 changed profile(s).'
"$microvisor_path" status | grep -Fq "$profile_id"$'\tapplied\t'
mv "$config_file" "$config_file.disabled"
write_empty_config
if "$microvisor_path" status >"$result_directory/removed-from-config.status"; then
  echo "Status unexpectedly ignored an installed profile removed from the desired list" >&2
  exit 1
fi
grep -Fq "$profile_id"$'\tinstalled-without-config\t' \
  "$result_directory/removed-from-config.status"
rm -f -- "$config_file"
mv "$config_file.disabled" "$config_file"

module_present "$module"
module_present "$deny_module"
[[ $(selinux_type "$executable") == "$exec_type" ]]
[[ -f "$state_file" ]]
[[ $(stat -c %a /var/lib/microvisor/profiles) == 700 ]]
[[ $(stat -c %a "$state_file") == 600 ]]
fcontext_present "$executable_regex"
fcontext_present "$data_regex"

"$executable" -c 'while :; do sleep 1; done' &
supervised_pid=$!
for _ in $(seq 1 20); do
  [[ $(cat "/proc/$supervised_pid/attr/current") == *":$app_type:"* ]] && break
  sleep 0.1
done
[[ $(cat "/proc/$supervised_pid/attr/current") == *":$app_type:"* ]]
"$microvisor_path" supervise >"$result_directory/supervise.txt"
grep -Fq 'Microvisor supervise — SELinux Enforcing' "$result_directory/supervise.txt"
grep -Fq $'Microvisor\tpid='"$supervised_pid"$'\t'"$app_type" \
  "$result_directory/supervise.txt"
kill "$supervised_pid"
wait "$supervised_pid" || true
supervised_pid=

filesystem_classes=(dir file lnk_file chr_file blk_file sock_file fifo_file)
for object_class in "${filesystem_classes[@]}"; do
  unconfined_rules="$result_directory/unconfined-${object_class}.rules"
  sesearch -A -s unconfined_t -t "$data_type" -c "$object_class" >"$unconfined_rules"
  if grep -q '^allow ' "$unconfined_rules"; then
    echo "unconfined_t unexpectedly retains $object_class access to $data_type" >&2
    cat "$unconfined_rules" >&2
    exit 1
  fi
done

app_read_rules="$result_directory/app-data-file-read.rules"
sesearch -A -s "$app_type" -t "$data_type" -c file -p read >"$app_read_rules"
if ! grep -q '^allow ' "$app_read_rules"; then
  echo "$app_type unexpectedly lacks file read access to $data_type" >&2
  cat "$app_read_rules" >&2
  exit 1
fi

if /usr/bin/cat "$secret_file" >/dev/null 2>"$result_directory/direct-access.err"; then
  echo "Direct access from unconfined_t unexpectedly succeeded" >&2
  exit 1
fi

protected_type=$("$executable" -c 'stat -c %C "$1" | cut -d: -f3' -- "$secret_file")
[[ "$protected_type" == "$data_type" ]]
[[ $("$executable" -c 'cat "$1"' -- "$secret_file") == microvisor-ci-secret ]]

"$microvisor_path" remove "$profile_id"

! module_present "$deny_module"
! module_present "$module"
! fcontext_present "$executable_regex"
! fcontext_present "$data_regex"
[[ ! -e "$state_file" ]]
[[ $(selinux_type "$executable") != "$exec_type" ]]
[[ $(selinux_type "$secret_file") != "$data_type" ]]
[[ $(/usr/bin/cat "$secret_file") == microvisor-ci-secret ]]

transaction_started=false

mkdir -p "$equivalence_root" "$equivalence_data_directory"
cp /usr/bin/bash "$equivalence_executable"
chmod 0755 "$equivalence_executable"
restorecon -RF "$equivalence_root" "$equivalence_data_directory"

cat >"$config_file" <<EOF
schema_version: 1
profiles:
  - id: $equivalence_profile_id
    name: File-context equivalence test
    executable: $equivalence_executable
    data_directories:
      - $equivalence_data_directory
    launch_domain: unconfined_t
    launch_role: unconfined_r
    block_ptrace: true
    block_fd_use: false
EOF
chmod 0600 "$config_file"

equivalence_transaction_started=true
"$microvisor_path" apply
module_present "$equivalence_module"
module_present "$equivalence_deny_module"
fcontext_present "$equivalence_executable_regex"
[[ $(selinux_type "$equivalence_executable") == "$equivalence_exec_type" ]]
[[ -f "$equivalence_state_file" ]]

"$microvisor_path" remove "$equivalence_profile_id"
! module_present "$equivalence_module"
! module_present "$equivalence_deny_module"
! fcontext_present "$equivalence_executable_regex"
[[ $(selinux_type "$equivalence_executable") != "$equivalence_exec_type" ]]
[[ ! -e "$equivalence_state_file" ]]
equivalence_transaction_started=false

write_empty_config
"$microvisor_path" validate | grep -Fq 'Validated 0 profile(s).'
echo "SELinux integration test passed."
