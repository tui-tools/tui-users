// Package accounts defines the backend-agnostic model tui-users renders and
// the interface every account backend satisfies. The UI knows only these
// types: it never builds a useradd, gpasswd or chage argv itself. Mutations
// are Command values produced by the backend, shown in a preview dialog and
// only then executed.
package accounts

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-kit/runner"
)

// Command is a single privileged invocation the user is about to run. Argv
// excludes any privilege wrapper: the backend adds it when previewing and when
// executing.
//
// It is an alias rather than a type of its own, so a backend hands the very
// value the confirm dialog displayed straight to the kit runner, with no
// conversion in between. That identity is what makes the preview a promise.
type Command = runner.Command

// The states a stored password can be in. They are the answer to "can this
// account be logged into with a password", which is not the same question as
// "can it be logged into at all" — an account with a locked password and an
// authorized key is still reachable over SSH, and the detail screen says so.
const (
	// PasswordUsable is a normal hashed password.
	PasswordUsable = "usable"
	// PasswordLocked is a hash prefixed with "!" — what `usermod -L` and
	// `passwd -l` both do. The hash is intact underneath.
	PasswordLocked = "locked"
	// PasswordEmpty is an empty second field: no password at all, which lets
	// anyone log in as the account.
	PasswordEmpty = "empty"
	// PasswordNever is "*" or "!!": no password was ever set, so password
	// authentication cannot succeed. It is what a service account has.
	PasswordNever = "never-set"
	// PasswordUnknown is what the tool reports when it could not read
	// /etc/shadow, which needs root.
	PasswordUnknown = "unknown"
)

// The severities a flag carries. They order the list: the account that can
// take the machine over sits above the one whose password never expires.
const (
	// SeverityCritical is a finding that hands someone else the machine.
	SeverityCritical = "critical"
	// SeverityWarning is a finding worth a second look.
	SeverityWarning = "warning"
	// SeverityNotice is a policy observation, not a break-in.
	SeverityNotice = "notice"
)

// severityRank orders the severities, most serious first.
var severityRank = map[string]int{
	SeverityCritical: 0,
	SeverityWarning:  1,
	SeverityNotice:   2,
}

// Flag is one reason an account is listed before the others: what was found,
// and how serious it is.
type Flag struct {
	Severity string
	// Reason is one sentence, written to be read in a table column.
	Reason string
}

// Aging is the password and account expiry policy, as /etc/shadow records it.
// Every field is optional: a machine where shadow could not be read carries
// none of them.
type Aging struct {
	// LastChange is the day the password was last changed, as a date, or
	// "never".
	LastChange string
	// Expires is the account expiry date, empty when the account never
	// expires.
	Expires string
	// MaxDays is how long a password may live. -1 means unlimited, which
	// shadow spells 99999 or an empty field.
	MaxDays int
	// MinDays, WarnDays and Inactive are the rest of the policy, -1 when
	// unset.
	MinDays  int
	WarnDays int
	Inactive int
	// Known reports whether any of this was actually read.
	Known bool
}

// NoExpiry reports whether the password lives forever.
func (a Aging) NoExpiry() bool { return a.MaxDays < 0 || a.MaxDays >= 99999 }

// Key is one entry of an authorized_keys file.
type Key struct {
	// Type is the key type as the file spells it ("ssh-ed25519").
	Type string
	// Comment is the trailing comment, usually user@host.
	Comment string
	// Fingerprint is what `ssh-keygen -lf` printed for this key, empty when
	// ssh-keygen was not available.
	Fingerprint string
	// Bits is the key size ssh-keygen reported, 0 when unknown.
	Bits int
	// Options are the leading options of a restricted line
	// ("no-pty,command=…"), empty on a plain key.
	Options string
	// Line is the line number in the file, 1-based, which is what the remove
	// action rewrites the file without.
	Line int
	// Raw is the line as it stands on disk.
	Raw string
}

// Label renders a key for a one-line list.
func (k Key) Label() string {
	parts := []string{k.Type}
	if k.Fingerprint != "" {
		parts = append(parts, k.Fingerprint)
	}
	if k.Comment != "" {
		parts = append(parts, k.Comment)
	}
	return strings.Join(parts, "  ")
}

// Session is one login session, as logind reports it.
type Session struct {
	ID     string
	User   string
	TTY    string
	Type   string
	Remote string
	Since  string
}

// Sudo is what a user may do through sudo.
type Sudo struct {
	// Groups are the sudo-granting groups the user is a member of
	// ("wheel", "sudo"), which is how nearly every distribution grants it.
	Groups []string
	// Rules are the lines `sudo -l -U <user>` reported, which is the
	// authoritative answer and needs root to ask.
	Rules []string
	// NoPasswd reports that at least one of those rules runs without a
	// password.
	NoPasswd bool
	// Note explains why Rules is empty when it is ("needs root to ask").
	Note string
}

// Granted reports whether anything suggests this user has sudo.
func (s Sudo) Granted() bool { return len(s.Groups) > 0 || len(s.Rules) > 0 }

// User is one local account.
type User struct {
	Name  string
	UID   int
	GID   int
	GECOS string
	Home  string
	Shell string
	// PrimaryGroup is the name of the GID group, or the number when no group
	// carries it.
	PrimaryGroup string
	// Groups are the supplementary groups, primary excluded, sorted.
	Groups []string
	// System reports an account outside the human UID range of
	// /etc/login.defs.
	System bool

	// Password is one of the Password* constants.
	Password string
	Aging    Aging

	// LastLogin is when the account last logged in, as the machine's own
	// tooling renders it, or "never".
	LastLogin string
	// LastLoginFrom is the terminal or host of that login.
	LastLoginFrom string

	// Keys are the account's authorized SSH keys.
	Keys []Key
	// KeysPath is the authorized_keys file they came from.
	KeysPath string
	// KeysNote explains an empty Keys list that is not simply empty
	// ("unreadable: needs root").
	KeysNote string

	Sudo     Sudo
	Sessions []Session

	// SELinuxLogin is the SELinux user this login maps to, when semanage
	// could be asked. Read-only: tui-users does not manage the mapping.
	SELinuxLogin string

	// Flags are the reasons this account is listed first.
	Flags []Flag
	// Detailed reports that the per-user read has run, so the detail screen
	// can tell "none" from "not read yet".
	Detailed bool
}

// Flagged reports whether the account carries any finding.
func (u User) Flagged() bool { return len(u.Flags) > 0 }

// Severity is the worst severity among the account's flags.
func (u User) Severity() string {
	worst := ""
	for _, f := range u.Flags {
		if worst == "" || severityRank[f.Severity] < severityRank[worst] {
			worst = f.Severity
		}
	}
	return worst
}

// Reason is the flag shown in the list's own column: the worst one.
func (u User) Reason() string {
	worst := u.Severity()
	for _, f := range u.Flags {
		if f.Severity == worst {
			return f.Reason
		}
	}
	return ""
}

// Locked reports whether password authentication is refused for this account.
func (u User) Locked() bool {
	return u.Password == PasswordLocked || u.Password == PasswordNever
}

// LoginShell reports whether the account's shell is one a person can log in
// with, as opposed to nologin or false.
func (u User) LoginShell() bool { return IsLoginShell(u.Shell) }

// IsLoginShell reports whether a shell path lets a session start.
func IsLoginShell(shell string) bool {
	switch {
	case shell == "":
		// An empty shell field means /bin/sh, which is a login shell.
		return true
	case strings.HasSuffix(shell, "nologin"), strings.HasSuffix(shell, "/false"),
		strings.HasSuffix(shell, "/sync"), strings.HasSuffix(shell, "/shutdown"),
		strings.HasSuffix(shell, "/halt"):
		return false
	}
	return true
}

// Group is one local group.
type Group struct {
	Name string
	GID  int
	// Members are the supplementary members, as /etc/group lists them.
	Members []string
	// Primary are the users whose primary group this is. /etc/group does not
	// record them, so they are folded in from the passwd database — which is
	// the thing people get wrong when they read `getent group` by hand.
	Primary []string
	// System reports a group outside the human GID range.
	System bool
}

// All returns every member, primary and supplementary, sorted and de-duplicated.
func (g Group) All() []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range [][]string{g.Primary, g.Members} {
		for _, name := range list {
			if seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// SudoersEntry is one rule parsed out of a sudoers file.
type SudoersEntry struct {
	// File and Line say where the rule lives.
	File string
	Line int
	// Who is the user, %group or #uid the rule applies to.
	Who string
	// Text is the rule as written.
	Text string
	// NoPasswd reports a rule that runs without asking for a password.
	NoPasswd bool
	// AllCommands reports a rule granting every command.
	AllCommands bool
}

// SudoersFile is one sudoers file as it is on disk.
type SudoersFile struct {
	Path string
	// Raw is the text, kept for the detail screen.
	Raw string
	// Entries are the rules parsed out of it.
	Entries []SudoersEntry
	// Note explains a file that could not be read.
	Note string
}

// Limits are the UID and GID ranges /etc/login.defs declares, which is how a
// system account is told from a human one.
type Limits struct {
	UIDMin, UIDMax       int
	SysUIDMin, SysUIDMax int
	GIDMin, GIDMax       int
	// PassMaxDays is the default password lifetime for a new account.
	PassMaxDays int
	// Source is the file the ranges came from, empty when the defaults were
	// used.
	Source string
}

// DefaultLimits are the values shadow-utils compiles in, used when
// /etc/login.defs is missing or says nothing.
func DefaultLimits() Limits {
	return Limits{
		UIDMin: 1000, UIDMax: 60000,
		SysUIDMin: 201, SysUIDMax: 999,
		GIDMin: 1000, GIDMax: 60000,
		PassMaxDays: -1,
	}
}

// Human reports whether a UID belongs to a person rather than to a service.
func (l Limits) Human(uid int) bool { return uid >= l.UIDMin && uid <= l.UIDMax }

// Model is the whole picture tui-users renders.
type Model struct {
	// Backend names the implementation that produced this model.
	Backend string
	// Root reports that the tool itself runs as root, which is what decides
	// whether the privileged reads were even attempted.
	Root bool
	// ShadowRead reports whether /etc/shadow could be read. Without it the
	// lock state and the expiry policy of every account are unknown, and the
	// UI says so rather than claiming every password is fine.
	ShadowRead bool
	// ShadowNote explains a failed shadow read in one sentence.
	ShadowNote string

	Users  []User
	Groups []Group
	// Sudoers are the sudoers files that could be read.
	Sudoers []SudoersFile
	// SudoersNote explains an empty Sudoers list.
	SudoersNote string
	// Sessions are the machine's current login sessions.
	Sessions []Session
	// SELinux reports that the machine has SELinux tooling, so the detail
	// screen shows the login mapping.
	SELinux bool

	Limits Limits
}

// User returns the account with the given name.
func (m Model) User(name string) (User, bool) {
	for _, u := range m.Users {
		if u.Name == name {
			return u, true
		}
	}
	return User{}, false
}

// Group returns the group with the given name.
func (m Model) Group(name string) (Group, bool) {
	for _, g := range m.Groups {
		if g.Name == name {
			return g, true
		}
	}
	return Group{}, false
}

// GroupNames returns every group name, sorted, which is what the group pickers
// are built from.
func (m Model) GroupNames() []string {
	out := make([]string, 0, len(m.Groups))
	for _, g := range m.Groups {
		out = append(out, g.Name)
	}
	sort.Strings(out)
	return out
}

// SessionsFor returns the sessions belonging to one user.
func (m Model) SessionsFor(name string) []Session {
	var out []Session
	for _, s := range m.Sessions {
		if s.User == name {
			out = append(out, s)
		}
	}
	return out
}

// NoPasswdCount is how many sudoers rules run without a password. It is the
// number `--check` reports, because it is the one line of a sudoers file that
// turns a compromised session into root.
func (m Model) NoPasswdCount() int {
	count := 0
	for _, file := range m.Sudoers {
		for _, entry := range file.Entries {
			if entry.NoPasswd {
				count++
			}
		}
	}
	return count
}

// Flagged returns the accounts carrying a finding, worst first.
func (m Model) Flagged() []User {
	var out []User
	for _, u := range m.Users {
		if u.Flagged() {
			out = append(out, u)
		}
	}
	return out
}

// SortUsers orders the list the way the tool shows it: flagged accounts first,
// worst finding at the top, then everything else by UID.
//
// It is the same idea as tui-systemd's failed units first — what is wrong with
// the machine should not have to be scrolled to.
func SortUsers(users []User) {
	sort.SliceStable(users, func(i, j int) bool {
		a, b := users[i], users[j]
		if a.Flagged() != b.Flagged() {
			return a.Flagged()
		}
		if a.Flagged() && b.Flagged() {
			if ra, rb := severityRank[a.Severity()], severityRank[b.Severity()]; ra != rb {
				return ra < rb
			}
		}
		return a.UID < b.UID
	})
}

// NewUser is what the create form asks for.
type NewUser struct {
	Name string
	// Shell is the login shell; empty leaves useradd's default.
	Shell string
	// Groups are supplementary groups to add the account to.
	Groups []string
	// CreateHome asks for -m; without it useradd creates no home directory.
	CreateHome bool
	// System asks for -r: an account outside the human UID range, with no
	// aging and no home by default.
	System bool
	// Comment is the GECOS field, usually the person's name.
	Comment string
}

// KeyPlan is a change to an authorized_keys file: what the file will look
// like, how that differs from what is there now, and the exact commands that
// apply it.
type KeyPlan struct {
	// Path is the authorized_keys file.
	Path string
	// Content is the text that will be installed, empty for an append that
	// never renders the whole file.
	Content string
	// Diff is the unified diff against the current file.
	Diff string
	// TempPath is the staging file an install command copies from, empty when
	// there is none.
	TempPath string
	// Commands are run in order, and are what the confirm dialog shows.
	Commands []Command
}

// Capabilities tells the UI what a backend supports, so the key map and the
// forms are built from the backend rather than hardcoded.
type Capabilities struct {
	// Shells are the login shells offered by the shell picker, read from
	// /etc/shells.
	Shells []string
	// SudoGroups are the groups that grant sudo on this machine ("wheel",
	// "sudo"), used to answer "does this account have sudo" without root.
	SudoGroups []string
	// The actions the backend can build. A backend that cannot do one drops
	// the key from the hint bar rather than failing when it is pressed.
	SupportsCreate   bool
	SupportsDelete   bool
	SupportsLock     bool
	SupportsPassword bool
	SupportsGroups   bool
	SupportsShell    bool
	SupportsExpiry   bool
	SupportsKeys     bool
}

// Backend is the boundary between the UI and the machine. Load reads state;
// the Build* methods turn user intent into previewable Commands; Run executes
// a Command the user confirmed. Nothing else may mutate the system.
type Backend interface {
	// Name is the backend identifier ("shadow-utils").
	Name() string
	// Describe is the one-line summary shown in the header.
	Describe() string
	// Capabilities reports what this backend supports.
	Capabilities() Capabilities

	// Preview renders the exact command line Run will execute, privilege
	// wrapper included. This is the text shown in the confirm dialog.
	Preview(cmd Command) string

	// Load reads every account, group and sudoers file.
	Load(ctx context.Context) (Model, error)
	// LoadUser re-reads one account in full: its authorized keys, its sudo
	// rules, its sessions and its aging, which the list read does not carry.
	LoadUser(ctx context.Context, user User) (User, error)
	// Run executes a previously previewed command.
	Run(ctx context.Context, cmd Command) (string, error)

	// BuildCreateUser builds the account creation.
	BuildCreateUser(spec NewUser) ([]Command, error)
	// BuildDeleteUser removes an account, with or without its home directory.
	BuildDeleteUser(name string, removeHome bool) (Command, error)
	// BuildLock locks or unlocks the account's password.
	BuildLock(name string, lock bool) (Command, error)
	// BuildSetPassword sets a password. The password travels on the command's
	// stdin, never in its argv.
	BuildSetPassword(name, password string) (Command, error)
	// BuildGroupMembership adds the user to a group or removes them from it.
	BuildGroupMembership(add bool, user, group string) (Command, error)
	// BuildSetShell changes the login shell.
	BuildSetShell(user, shell string) (Command, error)
	// BuildSetExpiry sets the account expiry date and the password lifetime.
	BuildSetExpiry(user, expires, maxDays string) ([]Command, error)
	// BuildAddKey appends an authorized key, after validating it.
	BuildAddKey(user User, key string) (KeyPlan, error)
	// BuildRemoveKey rewrites the file without one key.
	BuildRemoveKey(user User, key Key) (KeyPlan, error)
}

// UIDString renders a UID for a table cell.
func UIDString(uid int) string { return strconv.Itoa(uid) }
