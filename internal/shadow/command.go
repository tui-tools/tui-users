package shadow

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-users/internal/accounts"
)

// The version-gated capability of the openssh backend, named the way the
// manifest names it. shadow-utils declares none: it prints no version anywhere,
// so there is nothing to gate on.
const (
	// FeatureSecurityKeys is `sk-ssh-ed25519` and friends, which ssh-keygen
	// learned to read in OpenSSH 8.2. Below it a FIDO key in an
	// authorized_keys file fingerprints as an error rather than as a key.
	FeatureSecurityKeys = "security-keys"
)

// SSHDir is the directory an authorized_keys file lives in, relative to a home
// directory, and DirMode is the mode sshd insists on for it.
const (
	SSHDir      = ".ssh"
	KeysFile    = "authorized_keys"
	DirMode     = "700"
	KeyFileMode = "600"
)

// The sudo-granting groups, in the order distributions use them: wheel on
// Arch, Fedora and RHEL, sudo on Debian and Ubuntu. Membership is how the tool
// answers "does this account have sudo" without being root.
var sudoGroups = []string{"wheel", "sudo", "admin"}

// capabilities describes what the shadow-utils backend supports. It is shared
// by the real and the fake backend, so --demo behaves exactly like a real run.
var capabilities = accounts.Capabilities{
	SudoGroups:          sudoGroups,
	SupportsCreate:      true,
	SupportsDelete:      true,
	SupportsLock:        true,
	SupportsPassword:    true,
	SupportsGroups:      true,
	SupportsShell:       true,
	SupportsExpiry:      true,
	SupportsKeys:        true,
	SupportsGroupCreate: true,
	SupportsGroupDelete: true,
}

// Capabilities reports what the shadow-utils backend supports, with the shell
// list the caller read from /etc/shells folded in.
func Capabilities(shells []string) accounts.Capabilities {
	caps := capabilities
	caps.Shells = shells
	return caps
}

// nameRe is the set of names shadow-utils itself accepts: NAME_REGEX in
// /etc/adduser.conf terms, minus the distribution's local relaxations. Every
// command builder validates against it, because a user name is the argument
// that comes from the machine — or from a form — and ends up in an argv run as
// root.
var nameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}\$?$`)

// checkName rejects anything that is not a plausible account or group name.
func checkName(kind, name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("shadow: %q is not a valid %s name", name, kind)
	}
	return nil
}

// shellRe is an absolute path with nothing a shell would reinterpret. The
// picker offers what /etc/shells lists, but the field is free text, so this is
// what stands between a typo and an argv.
var shellRe = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

// checkShell rejects a shell that is not an absolute path.
func checkShell(shell string) error {
	if !shellRe.MatchString(shell) {
		return fmt.Errorf("shadow: %q is not an absolute path to a shell", shell)
	}
	return nil
}

// commentRe keeps the GECOS field to text: no colon, which is the passwd file's
// own separator, and no control characters.
var commentRe = regexp.MustCompile(`^[^:\n\r\t]*$`)

// BuildCreateUser turns the create form into a useradd command.
//
// The account is created with no password at all, which shadow spells "!" in
// the second field: it cannot be logged into until somebody sets one or adds a
// key. That is deliberate — a creation flow that also set a password would put
// one on screen.
func BuildCreateUser(spec accounts.NewUser) ([]accounts.Command, error) {
	if err := checkName("user", spec.Name); err != nil {
		return nil, err
	}
	if spec.Shell != "" {
		if err := checkShell(spec.Shell); err != nil {
			return nil, err
		}
	}
	if !commentRe.MatchString(spec.Comment) {
		return nil, fmt.Errorf("shadow: the comment cannot contain a colon or a newline")
	}
	for _, group := range spec.Groups {
		if err := checkName("group", group); err != nil {
			return nil, err
		}
	}
	if spec.System && spec.CreateHome {
		// useradd accepts -r -m, but the combination is almost always a
		// mistake: a service account with a skeleton home directory.
		return nil, fmt.Errorf(
			"shadow: a system account normally has no home directory; " +
				"turn one of the two off")
	}

	argv := []string{"useradd"}
	if spec.CreateHome {
		argv = append(argv, "-m")
	}
	if spec.System {
		argv = append(argv, "-r")
	}
	if spec.Shell != "" {
		argv = append(argv, "-s", spec.Shell)
	}
	if spec.Comment != "" {
		argv = append(argv, "-c", spec.Comment)
	}
	if len(spec.Groups) > 0 {
		argv = append(argv, "-G", strings.Join(spec.Groups, ","))
	}
	argv = append(argv, spec.Name)

	description := "Create the account " + spec.Name
	if spec.System {
		description = "Create the system account " + spec.Name
	}
	return []accounts.Command{{
		Argv:        argv,
		Description: description,
	}}, nil
}

// BuildDeleteUser removes an account. Removing the home directory is the
// destructive half, and it is a separate answer rather than a default.
func BuildDeleteUser(name string, removeHome bool) (accounts.Command, error) {
	if err := checkName("user", name); err != nil {
		return accounts.Command{}, err
	}
	if name == "root" {
		return accounts.Command{}, fmt.Errorf("shadow: root cannot be deleted")
	}
	argv := []string{"userdel"}
	description := "Delete the account " + name + ", keeping its home directory"
	if removeHome {
		argv = append(argv, "-r")
		description = "Delete the account " + name +
			" and remove its home directory and mail spool"
	}
	argv = append(argv, name)
	return accounts.Command{
		Argv: argv, Description: description, Destructive: true,
	}, nil
}

// BuildLock locks or unlocks an account's password.
//
// `usermod -L` prefixes the stored hash with "!", exactly as `passwd -l` does,
// and `-U` takes the prefix back off. The hash survives, so unlocking restores
// the old password — and locking stops password authentication only: an
// account with an authorized key can still log in over SSH. The dialog says so.
func BuildLock(name string, lock bool) (accounts.Command, error) {
	if err := checkName("user", name); err != nil {
		return accounts.Command{}, err
	}
	flag, description := "-U", "Unlock the password of "+name
	if lock {
		flag, description = "-L", "Lock the password of "+name
	}
	return accounts.Command{
		Argv:        []string{"usermod", flag, name},
		Description: description,
		Destructive: lock,
	}, nil
}

// BuildSetPassword sets an account's password through chpasswd.
//
// The password goes on the command's standard input, never in its argv: a
// command line is readable in `ps` by every user on the machine, and this tool
// puts the command line on screen as well. What the confirm dialog shows is
// `chpasswd` and nothing else; the value itself is masked everywhere.
func BuildSetPassword(name, password string) (accounts.Command, error) {
	if err := checkName("user", name); err != nil {
		return accounts.Command{}, err
	}
	switch {
	case password == "":
		return accounts.Command{}, fmt.Errorf("shadow: the password is empty")
	case strings.ContainsAny(password, ":\n\r"):
		// chpasswd reads "user:password" lines, so a colon or a newline would
		// change which account is being written to.
		return accounts.Command{}, fmt.Errorf(
			"shadow: a password cannot contain a colon or a newline, " +
				"because chpasswd reads user:password lines")
	}
	return accounts.Command{
		Argv:        []string{"chpasswd"},
		Stdin:       name + ":" + password + "\n",
		Description: "Set the password of " + name + " (read from standard input)",
		Destructive: true,
	}, nil
}

// BuildGroupMembership adds a user to a group or removes them from it.
func BuildGroupMembership(add bool, user, group string) (accounts.Command, error) {
	if err := checkName("user", user); err != nil {
		return accounts.Command{}, err
	}
	if err := checkName("group", group); err != nil {
		return accounts.Command{}, err
	}
	flag, description := "-d", "Remove "+user+" from the group "+group
	if add {
		flag, description = "-a", "Add "+user+" to the group "+group
	}
	return accounts.Command{
		Argv:        []string{"gpasswd", flag, user, group},
		Description: description,
		// Adding somebody to wheel is a privilege change, and removing them
		// from it can lock the only administrator out of their own machine.
		Destructive: true,
	}, nil
}

// BuildSudo grants or revokes sudo by editing the membership of the group that
// grants it on this machine — wheel on Arch, Fedora and RHEL, sudo on Debian
// and Ubuntu. The group is the caller's, read off the machine rather than
// guessed here.
//
// It is BuildGroupMembership with a description that says what the change
// means, because "add alice to wheel" and "grant alice sudo" are the same
// command and only one of them is the sentence somebody meant.
func BuildSudo(grant bool, user, group string) (accounts.Command, error) {
	cmd, err := BuildGroupMembership(grant, user, group)
	if err != nil {
		return accounts.Command{}, err
	}
	cmd.Description = "Revoke sudo from " + user +
		" by removing them from the group " + group
	if grant {
		cmd.Description = "Grant sudo to " + user +
			" by adding them to the group " + group
	}
	return cmd, nil
}

// maxGID is the highest GID this tool will ask groupadd for. It is the GID_MAX
// shadow-utils ships in /etc/login.defs: a number above it is a typo far more
// often than it is a decision, and groupadd is not the place to find that out.
const maxGID = 60000

// BuildCreateGroup turns the new-group form into a groupadd command.
//
// The GID is optional, and empty is the normal answer: groupadd then picks the
// next free number out of the machine's own range. A GID that was typed is
// validated here, because it reaches an argv run as root.
func BuildCreateGroup(spec accounts.NewGroup) (accounts.Command, error) {
	if err := checkName("group", spec.Name); err != nil {
		return accounts.Command{}, err
	}
	argv := []string{"groupadd"}
	description := "Create the group " + spec.Name
	if value := strings.TrimSpace(spec.GID); value != "" {
		gid, err := strconv.Atoi(value)
		if err != nil || gid < 0 || gid > maxGID {
			return accounts.Command{}, fmt.Errorf(
				"shadow: the GID must be a number between 0 and %d", maxGID)
		}
		// Atoi's own rendering, so "007" reaches groupadd as 7.
		argv = append(argv, "-g", strconv.Itoa(gid))
		description += " with gid " + strconv.Itoa(gid)
	}
	argv = append(argv, spec.Name)
	return accounts.Command{Argv: argv, Description: description}, nil
}

// BuildDeleteGroup removes a group.
//
// A group with members is refused rather than emptied: groupdel refuses a
// primary one anyway, and dropping a supplementary group from every account
// that held it is exactly the change nobody meant to make by pressing one key.
//
// A system group — one outside the machine's own GID range, which is what
// Group.System reports — is refused unless allowSystem says the extra
// confirmation was given. A package created it and expects it to be there.
func BuildDeleteGroup(group accounts.Group, allowSystem bool) (accounts.Command, error) {
	if err := checkName("group", group.Name); err != nil {
		return accounts.Command{}, err
	}
	if len(group.Primary) > 0 {
		return accounts.Command{}, fmt.Errorf(
			"shadow: %s is the primary group of %s, and groupdel refuses that",
			group.Name, strings.Join(group.Primary, ", "))
	}
	if members := group.All(); len(members) > 0 {
		return accounts.Command{}, fmt.Errorf(
			"shadow: the group %s still has %d member(s) — %s — so it is not empty",
			group.Name, len(members), strings.Join(members, ", "))
	}
	if group.System && !allowSystem {
		return accounts.Command{}, fmt.Errorf(
			"shadow: %s is a system group (gid %d), which a package owns",
			group.Name, group.GID)
	}
	return accounts.Command{
		Argv:        []string{"groupdel", group.Name},
		Description: "Delete the group " + group.Name,
		Destructive: true,
	}, nil
}

// BuildSetShell changes an account's login shell.
func BuildSetShell(user, shell string) (accounts.Command, error) {
	if err := checkName("user", user); err != nil {
		return accounts.Command{}, err
	}
	if err := checkShell(shell); err != nil {
		return accounts.Command{}, err
	}
	return accounts.Command{
		Argv:        []string{"usermod", "-s", shell, user},
		Description: "Set the login shell of " + user + " to " + shell,
		Destructive: true,
	}, nil
}

// dateRe is the one date format chage is asked for: ISO 8601, which it accepts
// on every distribution and which cannot be read two ways.
var dateRe = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

// NeverExpires is the value the expiry form takes for "no expiry at all". It
// becomes -1, which is how chage spells it.
const NeverExpires = "never"

// BuildSetExpiry sets the account expiry date and the password lifetime.
//
// Both are one `chage` call each rather than one call with two flags, because
// the two answers are independent: a form that left the password lifetime
// empty must not silently reset it.
func BuildSetExpiry(user, expires, maxDays string) ([]accounts.Command, error) {
	if err := checkName("user", user); err != nil {
		return nil, err
	}
	var commands []accounts.Command

	switch value := strings.TrimSpace(expires); {
	case value == "":
	case value == NeverExpires:
		commands = append(commands, accounts.Command{
			Argv:        []string{"chage", "-E", "-1", user},
			Description: "Let the account " + user + " never expire",
			Destructive: true,
		})
	case dateRe.MatchString(value):
		commands = append(commands, accounts.Command{
			Argv:        []string{"chage", "-E", value, user},
			Description: "Expire the account " + user + " on " + value,
			Destructive: true,
		})
	default:
		return nil, fmt.Errorf(
			"shadow: the expiry date must be YYYY-MM-DD or %q", NeverExpires)
	}

	switch value := strings.TrimSpace(maxDays); value {
	case "":
	case NeverExpires:
		commands = append(commands, accounts.Command{
			Argv:        []string{"chage", "-M", "-1", user},
			Description: "Let the password of " + user + " never expire",
			Destructive: true,
		})
	default:
		days, err := strconv.Atoi(value)
		if err != nil || days < 1 || days > 99999 {
			return nil, fmt.Errorf(
				"shadow: the password lifetime must be a number of days, or %q",
				NeverExpires)
		}
		commands = append(commands, accounts.Command{
			Argv: []string{"chage", "-M", value, user},
			Description: "Expire the password of " + user + " every " +
				value + " days",
			Destructive: true,
		})
	}

	if len(commands) == 0 {
		return nil, fmt.Errorf("shadow: nothing to change")
	}
	return commands, nil
}

// KeysPath is the authorized_keys file of a home directory.
func KeysPath(home string) string { return path.Join(home, SSHDir, KeysFile) }

// checkHome refuses a home directory that could send a privileged write
// somewhere it must never go. The path comes from the passwd database, which is
// as trustworthy as the machine — and the machine is what this tool is meant
// to survive being wrong about.
func checkHome(home string) error {
	switch {
	case !strings.HasPrefix(home, "/"):
		return fmt.Errorf("shadow: %q is not an absolute home directory", home)
	case home == "/":
		return fmt.Errorf("shadow: / is not a home directory")
	case strings.Contains(home, ".."), strings.ContainsAny(home, " \t\n"):
		return fmt.Errorf("shadow: %q is not a usable home directory", home)
	}
	return nil
}

// keyLineRe is the shape of an authorized_keys entry this tool will write: a
// key type, a base64 blob and an optional comment. Options ("no-pty,…") are
// deliberately refused on input — a restricted line is worth writing by hand,
// and the file's existing ones are shown and can be removed.
var keyLineRe = regexp.MustCompile(
	`^(sk-)?(ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|` +
		`ecdsa-sha2-nistp521|ssh-ed25519@openssh\.com|ecdsa-sk|ed25519-sk)` +
		`(@openssh\.com)? [A-Za-z0-9+/=]+( [^\n\r]*)?$`)

// CheckKeyLine reports whether a pasted line looks like a public key at all.
// It is the cheap check; the real one is `ssh-keygen -lf`, which the backend
// runs against the line staged in a temporary file before anything is written.
func CheckKeyLine(line string) error {
	line = strings.TrimSpace(line)
	switch {
	case line == "":
		return fmt.Errorf("shadow: no key was pasted")
	case strings.ContainsAny(line, "\n\r"):
		return fmt.Errorf("shadow: paste one key, on one line")
	case strings.HasPrefix(line, "-----BEGIN"):
		return fmt.Errorf(
			"shadow: that is a private key — paste the .pub file instead")
	case !keyLineRe.MatchString(line):
		return fmt.Errorf(
			"shadow: that does not look like a public key line " +
				"(type, base64 blob, optional comment)")
	}
	return nil
}

// BuildEnsureKeysDir builds the command that creates ~/.ssh with the mode sshd
// requires, owned by the account. `install -d` is used rather than mkdir
// because it sets the mode and the owner in the same call, so there is no
// window where the directory exists with the wrong permissions.
func BuildEnsureKeysDir(user accounts.User) (accounts.Command, error) {
	if err := checkHome(user.Home); err != nil {
		return accounts.Command{}, err
	}
	if err := checkName("user", user.Name); err != nil {
		return accounts.Command{}, err
	}
	dir := path.Join(user.Home, SSHDir)
	return accounts.Command{
		Argv: []string{"install", "-d", "-m", DirMode,
			"-o", user.Name, "-g", ownerGroup(user), dir},
		Description: "Make sure " + dir + " exists, mode " + DirMode +
			", owned by " + user.Name,
	}, nil
}

// BuildCreateKeysFile builds the command that creates an empty authorized_keys
// owned by the account, for the case where there is none yet. Copying
// /dev/null through `install` is what gets the owner and the mode right in one
// step; without it `tee` would create the file as root, mode 0644.
func BuildCreateKeysFile(user accounts.User) (accounts.Command, error) {
	if err := checkHome(user.Home); err != nil {
		return accounts.Command{}, err
	}
	if err := checkName("user", user.Name); err != nil {
		return accounts.Command{}, err
	}
	file := KeysPath(user.Home)
	return accounts.Command{
		Argv: []string{"install", "-m", KeyFileMode, "-o", user.Name,
			"-g", ownerGroup(user), "/dev/null", file},
		Description: "Create " + file + ", mode " + KeyFileMode + ", owned by " +
			user.Name,
	}, nil
}

// BuildAppendKey builds the append itself. The key travels on stdin, so the
// command line carries the file and nothing else — a public key is not a
// secret, but the same rule applies to every input this tool feeds a command.
func BuildAppendKey(user accounts.User, key string) (accounts.Command, error) {
	if err := checkHome(user.Home); err != nil {
		return accounts.Command{}, err
	}
	if err := CheckKeyLine(key); err != nil {
		return accounts.Command{}, err
	}
	file := KeysPath(user.Home)
	return accounts.Command{
		Argv:        []string{"tee", "-a", file},
		Stdin:       strings.TrimSpace(key) + "\n",
		Description: "Append the key to " + file,
		Destructive: true,
	}, nil
}

// BuildInstallKeys builds the command that replaces an authorized_keys file
// with a staged copy, which is how a key is removed: the file is rewritten
// without it, and the diff is shown before anything is installed.
func BuildInstallKeys(user accounts.User, tempPath string) (accounts.Command, error) {
	if err := checkHome(user.Home); err != nil {
		return accounts.Command{}, err
	}
	if err := checkName("user", user.Name); err != nil {
		return accounts.Command{}, err
	}
	file := KeysPath(user.Home)
	return accounts.Command{
		Argv: []string{"install", "-m", KeyFileMode, "-o", user.Name,
			"-g", ownerGroup(user), tempPath, file},
		Description: "Install the rewritten " + file,
		Destructive: true,
	}, nil
}

// ownerGroup is the group an account's files belong to: its primary group by
// name, or the numeric GID when no group carries it.
func ownerGroup(user accounts.User) string {
	if nameRe.MatchString(user.PrimaryGroup) {
		return user.PrimaryGroup
	}
	return strconv.Itoa(user.GID)
}

// WithoutKey returns the file text with one line removed, and reports whether
// it was there. The rest of the file is untouched, comments and options
// included: this tool rewrites nothing it did not have to.
func WithoutKey(raw string, key accounts.Key) (string, bool) {
	lines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
	if key.Line < 1 || key.Line > len(lines) {
		return raw, false
	}
	if strings.TrimSpace(lines[key.Line-1]) != strings.TrimSpace(key.Raw) {
		// The file changed under us since it was read; refusing is better than
		// deleting whatever moved into that line.
		return raw, false
	}
	kept := append([]string{}, lines[:key.Line-1]...)
	kept = append(kept, lines[key.Line:]...)
	if len(kept) == 0 {
		return "", true
	}
	return strings.Join(kept, "\n") + "\n", true
}

// diffContext is how many unchanged lines are shown around a change. Two is
// enough to place a key in a file of them without turning the confirm dialog
// into a wall of base64.
const diffContext = 2

// Diff renders a unified diff between two versions of a file.
//
// It is a real line diff — a longest-common-subsequence walk — rather than
// "everything out, everything in", because the confirm dialog for a key change
// has one job: show which key is going. A diff that repeats every other key
// buries exactly that.
//
// The files here are a handful of lines, so the quadratic table costs nothing.
func Diff(filePath, before, after string) string {
	if before == after {
		return ""
	}
	oldLines, newLines := splitLines(before), splitLines(after)
	ops := diffOps(oldLines, newLines)
	hunks := hunksOf(ops)
	if len(hunks) == 0 {
		return ""
	}

	var b strings.Builder
	fmt.Fprintf(&b, "--- %s\n", labelFor(filePath, before))
	fmt.Fprintf(&b, "+++ %s\n", filePath)
	for _, h := range hunks {
		oldCount, newCount := 0, 0
		for _, o := range h.ops {
			if o.kind != '+' {
				oldCount++
			}
			if o.kind != '-' {
				newCount++
			}
		}
		fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n",
			h.oldStart+1, oldCount, h.newStart+1, newCount)
		for _, o := range h.ops {
			fmt.Fprintf(&b, "%c%s\n", o.kind, o.text)
		}
	}
	return b.String()
}

// op is one line of a diff: kept (' '), removed ('-') or added ('+').
type op struct {
	kind byte
	text string
	// oldIndex and newIndex are the line's position in each file, used to
	// number the hunk headers.
	oldIndex, newIndex int
}

// diffOps walks the longest common subsequence of the two line lists and
// returns the operations that turn the first into the second.
func diffOps(oldLines, newLines []string) []op {
	lcs := make([][]int, len(oldLines)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(newLines)+1)
	}
	for i := len(oldLines) - 1; i >= 0; i-- {
		for j := len(newLines) - 1; j >= 0; j-- {
			if oldLines[i] == newLines[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
				continue
			}
			lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
		}
	}

	var ops []op
	i, j := 0, 0
	for i < len(oldLines) && j < len(newLines) {
		switch {
		case oldLines[i] == newLines[j]:
			ops = append(ops, op{' ', oldLines[i], i, j})
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
			ops = append(ops, op{'-', oldLines[i], i, j})
			i++
		default:
			ops = append(ops, op{'+', newLines[j], i, j})
			j++
		}
	}
	for ; i < len(oldLines); i++ {
		ops = append(ops, op{'-', oldLines[i], i, j})
	}
	for ; j < len(newLines); j++ {
		ops = append(ops, op{'+', newLines[j], i, j})
	}
	return ops
}

// hunk is a run of changes with its surrounding context.
type hunk struct {
	oldStart, newStart int
	ops                []op
}

// hunksOf groups the operations into hunks, keeping diffContext unchanged
// lines around each change and merging changes close enough to share them.
func hunksOf(ops []op) []hunk {
	keep := make([]bool, len(ops))
	for i, o := range ops {
		if o.kind == ' ' {
			continue
		}
		for j := max(i-diffContext, 0); j <= min(i+diffContext, len(ops)-1); j++ {
			keep[j] = true
		}
	}

	var hunks []hunk
	var current *hunk
	for i, o := range ops {
		if !keep[i] {
			current = nil
			continue
		}
		if current == nil {
			hunks = append(hunks, hunk{oldStart: o.oldIndex, newStart: o.newIndex})
			current = &hunks[len(hunks)-1]
		}
		current.ops = append(current.ops, o)
	}
	return hunks
}

// labelFor names the left side of the diff: the file, or /dev/null when it does
// not exist yet.
func labelFor(filePath, before string) string {
	if before == "" {
		return "/dev/null"
	}
	return filePath
}

// splitLines splits a file into lines, dropping the empty element a trailing
// newline produces.
func splitLines(text string) []string {
	if text == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}
