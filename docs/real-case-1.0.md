# Real case for 1.0: an account's whole life on a Fedora server

Point 5 of the family's [stability bar](https://github.com/tui-tools/tui-kit/blob/main/docs/stability.md):
the tool has driven a real machine end to end for its main purpose, and what
that surfaced was fixed or filed.

## The machine, plainly

A lab virtual machine, not a production server: Fedora 44 Cloud Edition
(systemd 259, SELinux enforcing, OpenSSH 10.2), booted by
[tui-lab](https://github.com/tui-tools/tui-lab) under KVM on the project's own
server. The tool ran as the ordinary user `lab` over SSH, escalating with
`sudo -n`; the client that logged in as the new account was the host, through
the VM's forwarded SSH port. The build was `main` on 2026-11-18, and from the
delete step on, `main` with [#32](https://github.com/tui-tools/tui-users/pull/32).

The same build also ran read-only on the project's own server, a Fedora 44
machine in daily use: `tui-users --check` exited 0 with `/etc/shadow` read
through `sudo -n`. Nothing was changed on that machine.

## What was done, end to end

1. `n`: account `ana`, full name `Ana, operations`, group `wheel`. Previewed as
   `useradd -m -c 'Ana, operations' -G wheel ana`; `id ana` afterwards printed
   `groups=1002(ana),10(wheel)`.
2. `p`: a password typed into a field that echoes nothing, sent to `chpasswd`
   on standard input (the dialog shows `ana:••••••••`). `/etc/shadow` then held
   a yescrypt hash (`$y$`). The list flagged the account `password never
   expires`, which is Fedora's `PASS_MAX_DAYS 99999`.
3. `enter`, then `K`, add a key: three commands, all run as `ana` through
   `runuser` (`install -d -m 700 ~/.ssh`, `install -m 600 /dev/null
   authorized_keys`, `tee -a`). A login as `ana` with that key from the host
   worked, and `~/.ssh` was `drwx------ ana ana`.
4. `l`: `usermod -L ana`. The dialog said the lock stops passwords only and
   that the account had one key; a key login afterwards still worked, as it
   said.
5. `S`: revoke sudo by `gpasswd -d ana wheel`, with "1 other account(s) keep
   sudo through wheel" in the dialog. `id ana` afterwards: `groups=1002(ana)`.
6. `D`, delete with the home directory: `userdel -r ana`. Afterwards `getent
   passwd ana` and `getent group ana` found nothing and `/home/ana` was gone.

## What it surfaced

- After an SSH login as `ana` had ended, the detail screen still listed its
  session, `R` did not drop it, and `D` refused the account as logged in.
  Two causes: a re-read appended sessions to the ones already on screen, and
  systemd 256 and later list each account's service manager
  (`user@UID.service`) as a session of class `manager` that outlives the
  login by a few seconds. Fixed in
  [#32](https://github.com/tui-tools/tui-users/pull/32), with tests, and
  checked again on the same machine: during a login the detail screen showed
  the session, after it `R` showed none and `D` offered the delete.
- The accounts list cuts the PASSWORD column (`never-set +…`) while USER has
  room, and a session reads `from -`: filed as
  [#33](https://github.com/tui-tools/tui-users/issues/33).

## What it did not cover

Group creation and deletion, the expiry form (`e`), the shell form (`s`) and
the sudo rules screen were not exercised on this machine.
