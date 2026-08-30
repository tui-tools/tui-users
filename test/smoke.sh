#!/bin/bash
# Backend smoke test for tui-users, run inside a lab guest.
#
# The contract (see tui-tools/tui-lab): this script runs on the guest as the
# unprivileged lab user, escalates with `sudo -n` only, prints a short PASS/FAIL
# table and exits non-zero if anything failed. The binary under test is at
# $TUI_LAB_BIN (default: tui-users on PATH).
#
# What it proves is that the tool reads the machine's *real* accounts and agrees
# with the machine's own tooling — not that a fake renders. The lab already
# covers --version and a --demo frame; this covers the backend.
#
# Almost everything here is read-only. The one exception is guarded: when
# `sudo -n true` works, a throwaway account is created and deleted through the
# tool's own command builders, and an EXIT trap removes it however the script
# ends.
set -uo pipefail

bin="${TUI_LAB_BIN:-tui-users}"
# TOOL is the manifest name, which is what a compatibility result is keyed on.
TOOL=tui-users
# The account the write path is exercised with. It is created and deleted in
# the same run, and the EXIT trap removes it if anything goes wrong in between.
TESTUSER=tuitest
pass=0
fail=0

# check runs one assertion. It takes a label, a command and a grep pattern the
# command's output must match. Output is captured so a failure can show it.
check() {
  local label="$1" command="$2" pattern="$3" output status
  output=$(eval "$command" 2>&1)
  status=$?
  if [[ $status -eq 0 ]] && grep -qE "$pattern" <<<"$output"; then
    printf 'PASS  %s\n' "$label"
    pass=$((pass + 1))
  else
    printf 'FAIL  %s (exit %d)\n' "$label" "$status"
    sed 's/^/      | /' <<<"$output" | head -12
    fail=$((fail + 1))
  fi
}

# check_absent is the inverse of a grep assertion: the command must succeed and
# its output must NOT contain the pattern. It is what proves a password hash
# never leaves the backend, which is a claim about something that did not happen.
check_absent() {
  local label="$1" command="$2" pattern="$3" output status
  output=$(eval "$command" 2>&1)
  status=$?
  if [[ $status -eq 0 ]] && ! grep -qE "$pattern" <<<"$output"; then
    printf 'PASS  %s\n' "$label"
    pass=$((pass + 1))
  else
    printf 'FAIL  %s (exit %d)\n' "$label" "$status"
    sed 's/^/      | /' <<<"$output" | head -12
    fail=$((fail + 1))
  fi
}

# --- compatibility evidence -------------------------------------------------
#
# The manifest's `tested` list is generated, not claimed: it is rebuilt from
# compat/results.jsonl by tui-kit/tools/compat-sync.py, and this is where a
# line of that file comes from. The version recorded is the one the tool itself
# probed, read back out of --check.
#
# What gets recorded is the openssh version, because that is the only backend
# here with a version at all: shadow-utils prints none from any of its
# programs, its manifest block declares no version command, and there is
# therefore nothing to record about it. The distro field is what identifies the
# shadow-utils this run exercised.
record_compat() {
  local report="$1" outcome="$2" backend version distro today block
  block=$(sed -n '/"compat": {/,/^  }/p' <<<"$report")
  backend=$(sed -n 's/.*"backend": "\([^"]*\)".*/\1/p' <<<"$block" | head -1)
  version=$(sed -n 's/.*"version": "\([^"]*\)".*/\1/p' <<<"$block" | head -1)
  if [[ -z $backend || -z $version ]]; then
    echo "      no version was probed, so no compatibility result is recorded"
    return
  fi

  distro=$(. /etc/os-release && echo "${ID}-${VERSION_ID:-rolling}")
  today=$(date -u +%Y-%m-%d)
  local line
  line=$(printf '{"backend":"%s","date":"%s","distro":"%s","result":"%s","suite":"smoke","tool":"%s","version":"%s"}' \
    "$backend" "$today" "$distro" "$outcome" "$TOOL" "$version")

  printf 'compat-result: %s\n' "$line"
  if [[ -n ${TUI_COMPAT_RESULTS:-} ]]; then
    printf '%s\n' "$line" >>"$TUI_COMPAT_RESULTS"
  fi
}

# cleanup removes the throwaway account however this script ends. It runs even
# when the account was never created, which is why every failure is swallowed.
cleanup() {
  if id "$TESTUSER" >/dev/null 2>&1; then
    sudo -n userdel -r "$TESTUSER" >/dev/null 2>&1 ||
      sudo -n userdel "$TESTUSER" >/dev/null 2>&1
  fi
}
trap cleanup EXIT

echo "--- tui-users smoke on $(. /etc/os-release && echo "$PRETTY_NAME")"

if ! command -v getent >/dev/null; then
  echo "FAIL  getent is not installed on this machine"
  exit 1
fi

# Whether this run can change anything. `sudo -n true` is the same question the
# tool asks, and the answer decides which half of this script runs.
if sudo -n true 2>/dev/null; then
  escalates=yes
else
  escalates=no
fi
echo "      user=$(id -un)  sudo -n=$escalates"

# 1. The read path works at all and names the backend it drove. Reading the
#    passwd database takes no privileges, so this runs as the plain lab user —
#    which is itself the assertion that the tool does not escalate to look.
check "check reads the accounts unprivileged" \
  "$bin --check" \
  '"backend": "shadow-utils"'

# 2. The account count matches what getent lists. This is the real parser test:
#    a tool that fetched the output but failed to parse it reports zero.
users=$(getent passwd | wc -l)
check "account count matches \`getent passwd\` ($users)" \
  "$bin --check" \
  "\"users\": $users"

# 3. And the groups.
groups=$(getent group | wc -l)
check "group count matches \`getent group\` ($groups)" \
  "$bin --check" \
  "\"groups\": $groups"

# 4. root is on every machine, and it is uid 0.
check "root is parsed" \
  "$bin --check" \
  '"Name": "root"'

# 5. The account running the test is listed, with its own uid. This is the
#    assertion that the parse is of *this* machine and not of a fixture.
check "the current user ($(id -un), uid $(id -u)) is listed" \
  "$bin --check" \
  "\"Name\": \"$(id -un)\""

# 6. The UID ranges come from /etc/login.defs, and they are what tells a
#    service account from a person's. A machine that reported zero would call
#    every account a system account.
uidmin=$(awk '$1 == "UID_MIN" { print $2 }' /etc/login.defs 2>/dev/null)
uidmin=${uidmin:-1000}
check "the uid range is read from /etc/login.defs (UID_MIN=$uidmin)" \
  "$bin --check" \
  "\"UIDMin\": $uidmin"

# 7. A password hash must never leave the backend. The model carries the
#    *state* of a password, never the hash, so a --check report is safe to
#    paste into a bug report.
check_absent "no password hash reaches the report" \
  "$bin --check" \
  '\$6\$|\$y\$|\$2b\$'

# 8. The sudo rules, when they can be read at all. /etc/sudoers is root-only on
#    every distribution, so this is asserted only where escalation works.
if [[ $escalates == yes ]]; then
  rules=$(sudo -n grep -cE '^[^#]*ALL' /etc/sudoers 2>/dev/null || echo 0)
  check "the sudoers file was read ($rules ALL lines in /etc/sudoers)" \
    "$bin --check" \
    '"sudoersFiles": [1-9]'

  # The lock state and the expiry of every account live in /etc/shadow, which
  # getent answers for only as root.
  check "/etc/shadow was read" \
    "$bin --check" \
    '"shadowRead": true'
else
  check "an unprivileged run says the password state is unknown" \
    "$bin --check" \
    '"shadowRead": false'
  check "and says why" \
    "$bin --check" \
    '"shadowNote": ".+"'
fi

# 9. --check must never change anything: the passwd database is identical after
#    it.
before=$(getent passwd)
$bin --check >/dev/null 2>&1
after=$(getent passwd)
if [[ "$before" == "$after" ]]; then
  printf 'PASS  --check left the accounts untouched\n'
  pass=$((pass + 1))
else
  printf 'FAIL  --check changed the passwd database\n'
  diff <(echo "$before") <(echo "$after") | sed 's/^/      | /' | head -12
  fail=$((fail + 1))
fi

# --- the report block ------------------------------------------------------
#
# --report is read-only and unprivileged, so it is smoked without sudo: a user
# who cannot escalate is exactly the one who most needs to be able to file a
# usable bug. What is asserted is that it agrees with the backend this machine
# is actually driving, that it still answers under --demo, and that it keeps
# its privacy promise — the block goes into a public issue, so a home path or
# the host name appearing in it is a bug, not a cosmetic detail.
check "report names the account backend" \
  "$bin --report" \
  '^backend: shadow-utils'

check "report says the run was live" \
  "$bin --report" \
  '^mode: live$'

check "report works in demo mode too" \
  "$bin --demo --report" \
  '^backend: demo$'

check "and says so on the mode line" \
  "$bin --demo --report" \
  '^mode: demo'

check "report leaks neither a home path nor the host name" \
  "$bin --report | grep -cE '/home/|$(uname -n)' || true" \
  '^0$'

# --- the write path ---------------------------------------------------------
#
# Only when escalation works without a password, and only against an account
# this script creates for the purpose. Every command here is the exact argv the
# tool builds and previews; the tool itself is not driven, because a TUI cannot
# be, and what is being proven is that those argvs work on this machine.
if [[ $escalates == yes ]]; then
  if id "$TESTUSER" >/dev/null 2>&1; then
    echo "SKIP  $TESTUSER already exists; the write path is not exercised"
  else
    check "useradd creates the throwaway account" \
      "sudo -n useradd -m -s /bin/bash $TESTUSER && id $TESTUSER" \
      "uid=[0-9]+\($TESTUSER\)"

    check "the tool sees the new account" \
      "$bin --check" \
      "\"Name\": \"$TESTUSER\""

    check "usermod -L locks it" \
      "sudo -n usermod -L $TESTUSER && sudo -n getent shadow $TESTUSER" \
      "^$TESTUSER:!"

    check "the tool reports it locked" \
      "$bin --check" \
      '"Password": "locked"'

    check "chpasswd takes the password on stdin" \
      "printf '%s:%s\n' $TESTUSER 'not-a-real-password' | sudo -n chpasswd && echo ok" \
      'ok'

    check "gpasswd adds it to a group" \
      "sudo -n gpasswd -a $TESTUSER $TESTUSER && getent group $TESTUSER" \
      "$TESTUSER\$"

    check "chage sets an expiry" \
      "sudo -n chage -E 2030-01-01 $TESTUSER && sudo -n chage -l $TESTUSER" \
      'Account expires.*2030'

    # A real key, generated here on the guest. The invented blob this used to
    # write was not a valid ed25519 point, and ssh-keygen refuses a file with
    # one in it outright — so the fingerprint assertion below could never have
    # passed on any machine, and proved nothing about the tool when it failed.
    keydir=$(mktemp -d)
    ssh-keygen -q -t ed25519 -N '' -C smoke@test -f "$keydir/id_ed25519"
    keyprint=$(ssh-keygen -lf "$keydir/id_ed25519.pub" | awk '{print $2}')
    # The fingerprint is base64, so `+` in it would be read as a repetition by
    # grep -E. Escape it before it becomes a pattern.
    keyprint_re=${keyprint//+/\\+}

    check "install and tee write an authorized_keys file" \
      "sudo -n install -d -m 700 -o $TESTUSER -g $TESTUSER /home/$TESTUSER/.ssh &&
       sudo -n install -m 600 -o $TESTUSER -g $TESTUSER \
         '$keydir/id_ed25519.pub' /home/$TESTUSER/.ssh/authorized_keys &&
       sudo -n stat -c '%U %a' /home/$TESTUSER/.ssh" \
      "$TESTUSER 700"

    # And now the tool reads it. The file is mode 600 inside a 700 directory
    # owned by another account, so an unprivileged read gets EACCES and the
    # tool has to escalate — the same trap /boot cost tui-snapper and the
    # netplan-rendered .network file cost tui-network. Demanding the exact
    # fingerprint ssh-keygen computes covers both halves: that the tool got
    # the file at all, and that it parsed what it got.
    check "the tool reads the key it cannot see unprivileged" \
      "$bin --check --user $TESTUSER" \
      "\"KeysPath\": \"/home/$TESTUSER/.ssh/authorized_keys\""

    check "the tool fingerprints that key as ssh-keygen does" \
      "$bin --check --user $TESTUSER" \
      "$keyprint_re"

    rm -rf "$keydir"

    check "userdel removes it again" \
      "sudo -n userdel -r $TESTUSER; ! id $TESTUSER 2>/dev/null && echo gone" \
      'gone'
  fi
else
  echo "SKIP  sudo -n does not work here, so the write path is not exercised"
fi

if [[ $fail -eq 0 ]]; then
  record_compat "$("$bin" --check 2>/dev/null)" pass
else
  record_compat "$("$bin" --check 2>/dev/null)" fail
fi

echo "--- tui-users: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
