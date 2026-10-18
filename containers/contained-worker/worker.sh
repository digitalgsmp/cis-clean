#!/bin/sh
set -eu
set -o pipefail

refuse() { echo "$1" >&2; exit "${2:-65}"; }

[ "$(id -u)" -ne 0 ] || refuse 'refusing root worker' 70
[ "$#" -eq 6 ] || refuse 'the frozen invocation has six exact arguments'
case "$1" in
  reconstruct-module|verify-authored-source) ;;
  *) refuse 'operation is not declared' ;;
esac
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

if [ "$1" = verify-authored-source ]; then
  # Untrusted, model-authored source and tests. The runner is baked into the
  # image at 0555 on a read-only root, never read from /contract, because a
  # verifier supplied by the thing being verified is not a verifier.
  [ -x /usr/local/bin/cis-verify-source ] || refuse 'trusted verification runner is absent' 66

  mkdir -p /workspace/run || refuse 'cannot create run directory' 67

  set +e
  CIS_CONTRACT_DIR=/contract CIS_RUN_DIR=/workspace/run \
    /usr/local/bin/cis-verify-source > /workspace/run/verdict.raw 2> /workspace/run/verify.stderr
  runner_exit=$?
  set -e

  # Exactly one line is trusted, and it is selected by prefix. Anything the
  # untrusted suite printed cannot be mistaken for the verdict.
  verdict_line="$(grep '^CIS_VERDICT ' /workspace/run/verdict.raw 2>/dev/null | tail -1 || true)"
  if [ -z "$verdict_line" ]; then
    verdict_json='{"verdict":"HARNESS_FAILURE","reason":"runner emitted no verdict","about_the_source":"NOTHING"}'
    verdict=HARNESS_FAILURE
  else
    verdict_json="${verdict_line#CIS_VERDICT }"
    verdict="$(printf '%s' "$verdict_json" | sed -n 's/.*"verdict"[ ]*:[ ]*"\([A-Z_]*\)".*/\1/p')"
    [ -n "$verdict" ] || verdict=HARNESS_FAILURE
  fi

  # Evidence is written by the WORKER, AFTER the untrusted process has exited,
  # so nothing the suite executed can author or edit its own verdict. Any file
  # the suite pre-created at this path is overwritten here.
  {
    echo 'schema=cis-contained-worker-evidence-v4'
    echo "run_nonce=$6"
    echo "uid=$(id -u)"
    echo "gid=$(id -g)"
    echo 'operation=verify_authored_source'
    echo "task_contract_bundle_sha256=$bundle_hash"
    echo "task_contract_hash=$3"
    echo "authorization_binding_hash=$4"
    echo "input_sha256=$input_hash"
    echo "verdict=$verdict"
    echo "runner_exit=$runner_exit"
    echo "verdict_json=$verdict_json"
    echo "nets=$(ls /sys/class/net | sort | tr '\n' ',')"
    echo "cap_eff=$(awk '/^CapEff:/ {print $2}' /proc/1/status)"
    echo "no_new_privs=$(awk '/^NoNewPrivs:/ {print $2}' /proc/1/status)"
    echo "pids_max=$(cat /sys/fs/cgroup/pids.max)"
    echo "memory_max=$(cat /sys/fs/cgroup/memory.max)"
    echo "cpu_max=$(cat /sys/fs/cgroup/cpu.max)"
    if touch /etc/cis-write-probe 2>/dev/null; then echo 'rootfs_write=allowed'; else echo 'rootfs_write=denied'; fi
    if touch /contract/cis-write-probe 2>/dev/null; then echo 'contract_write=allowed'; else echo 'contract_write=denied'; fi
    echo 'promotion=none'
    echo 'host_action=none'
  } > /workspace/worker-evidence.txt

  # The worker exits non-zero on anything but a pass, and NEVER promotes.
  case "$verdict" in
    SOURCE_PASS) exit 0 ;;
    SOURCE_FAIL) exit 1 ;;
    *) exit 2 ;;
  esac
fi

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
