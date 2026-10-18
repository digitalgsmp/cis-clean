#!/bin/sh
set -eu
set -o pipefail

refuse() { echo "$1" >&2; exit "${2:-65}"; }

[ "$(id -u)" -ne 0 ] || refuse 'refusing root worker' 70
[ "$#" -eq 6 ] || refuse 'the frozen invocation has six exact arguments'
[ "$1" = reconstruct-module ] || refuse 'operation is not declared'
[ -r /contract/task-contract.json ] || refuse 'frozen task contract is absent' 66
[ -r /contract/input.json ] || refuse 'frozen input is absent' 66
[ -d /workspace ] && [ -w /workspace ] || refuse 'workspace is not writable' 67

expected_bundle_hash="$2"
task_contract_hash="$3"
authorization_binding_hash="$4"
expected_input_hash="$5"
run_nonce="$6"
bundle_hash="$(sha256sum /contract/task-contract.json | awk '{print $1}')"
input_hash="$(sha256sum /contract/input.json | awk '{print $1}')"
[ "$bundle_hash" = "$expected_bundle_hash" ] || refuse 'task contract bundle digest mismatch' 68
[ "$input_hash" = "$expected_input_hash" ] || refuse 'worker input digest mismatch' 68

# This first real operation deliberately produces a candidate rather than
# executing model-authored code. It proves the complete governed handoff while
# preserving the promotion boundary for the independent gates that follow.
{
  echo 'schema=cis-contained-worker-candidate-v1'
  echo 'operation=reconstruct_module'
  echo "task_contract_hash=$task_contract_hash"
  echo "authorization_binding_hash=$authorization_binding_hash"
} > /workspace/candidate.txt
candidate_hash="$(sha256sum /workspace/candidate.txt | awk '{print $1}')"

nets="$(ls /sys/class/net | sort | tr '\n' ',')"
cap_eff="$(awk '/^CapEff:/ {print $2}' /proc/1/status)"
no_new_privs="$(awk '/^NoNewPrivs:/ {print $2}' /proc/1/status)"
pids_max="$(cat /sys/fs/cgroup/pids.max)"
memory_max="$(cat /sys/fs/cgroup/memory.max)"
cpu_max="$(cat /sys/fs/cgroup/cpu.max)"
if touch /etc/cis-write-probe 2>/dev/null; then rootfs_write=allowed; else rootfs_write=denied; fi
if touch /contract/cis-write-probe 2>/dev/null; then contract_write=allowed; else contract_write=denied; fi
if touch /workspace/cis-write-probe 2>/dev/null; then
  workspace_write=allowed
  rm -f /workspace/cis-write-probe
else
  workspace_write=denied
fi

{
  echo 'schema=cis-contained-worker-evidence-v3'
  echo "run_nonce=$run_nonce"
  echo "uid=$(id -u)"
  echo "gid=$(id -g)"
  echo 'operation=reconstruct_module'
  echo "task_contract_bundle_sha256=$bundle_hash"
  echo "task_contract_hash=$task_contract_hash"
  echo "authorization_binding_hash=$authorization_binding_hash"
  echo "input_sha256=$input_hash"
  echo "candidate_sha256=$candidate_hash"
  echo "nets=$nets"
  echo "cap_eff=$cap_eff"
  echo "no_new_privs=$no_new_privs"
  echo "pids_max=$pids_max"
  echo "memory_max=$memory_max"
  echo "cpu_max=$cpu_max"
  echo "rootfs_write=$rootfs_write"
  echo "contract_write=$contract_write"
  echo "workspace_write=$workspace_write"
  echo 'host_action=none'
} > /workspace/worker-evidence.txt
