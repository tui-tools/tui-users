package shadow

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tui-tools/tui-users/internal/accounts"
)

// read loads a fixture. The fixtures are the real output of the programs this
// backend drives, captured from machines running shadow-utils, with the names
// and the one routable network rewritten into the documentation ranges.
func read(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return string(data)
}

func TestParsePasswd(t *testing.T) {
	users := ParsePasswd(read(t, "getent-passwd.txt"))
	if len(users) != 8 {
		t.Fatalf("got %d accounts, want 8", len(users))
	}
	tests := []struct {
		index int
		name  string
		uid   int
		shell string
		home  string
	}{
		{0, "root", 0, "/bin/bash", "/root"},
		{4, "postgres", 26, "/bin/bash", "/var/lib/pgsql"},
		{5, "toolbox", 0, "/bin/bash", "/var/lib/toolbox"},
		{6, "alice", 1000, "/bin/bash", "/home/alice"},
	}
	for _, want := range tests {
		got := users[want.index]
		if got.Name != want.name || got.UID != want.uid ||
			got.Shell != want.shell || got.Home != want.home {
			t.Errorf("account %d = %+v, want %v", want.index, got, want)
		}
		if got.Password != accounts.PasswordUnknown {
			t.Errorf("%s: the passwd file says nothing about a password",
				got.Name)
		}
	}
}

func TestParseGroup(t *testing.T) {
	groups := ParseGroup(read(t, "getent-group.txt"))
	if len(groups) != 8 {
		t.Fatalf("got %d groups, want 8", len(groups))
	}
	byName := map[string]accounts.Group{}
	for _, group := range groups {
		byName[group.Name] = group
	}
	if wheel := byName["wheel"]; wheel.GID != 10 || len(wheel.Members) != 1 ||
		wheel.Members[0] != "alice" {
		t.Errorf("wheel = %+v", wheel)
	}
	if docker := byName["docker"]; len(docker.Members) != 2 {
		t.Errorf("docker members = %v, want two", docker.Members)
	}
	if root := byName["root"]; len(root.Members) != 0 {
		t.Errorf("an empty member field must parse as no members: %v", root.Members)
	}
}

// TestParseShadowClassifiesEveryPasswordForm covers the field that decides
// whether an account can be logged into with a password, in every spelling
// the distributions use.
func TestParseShadowClassifiesEveryPasswordForm(t *testing.T) {
	entries := ParseShadow(read(t, "getent-shadow.txt"))
	tests := map[string]string{
		"root":     accounts.PasswordUsable,
		"bin":      accounts.PasswordNever,
		"sshd":     accounts.PasswordNever,
		"postgres": accounts.PasswordNever,
		"toolbox":  accounts.PasswordUsable,
		"alice":    accounts.PasswordUsable,
		"bob":      accounts.PasswordEmpty,
	}
	for name, want := range tests {
		entry, ok := entries[name]
		if !ok {
			t.Fatalf("%s is missing from the parsed shadow", name)
		}
		if entry.State != want {
			t.Errorf("%s: state %q, want %q", name, entry.State, want)
		}
	}

	// A locked hash keeps its "!" prefix in front of a real hash, which is
	// what distinguishes a lock from an account that never had a password.
	locked := ParseShadow("carol:!$6$abc$0123:20000:0:99999:7:::\n")
	if got := locked["carol"].State; got != accounts.PasswordLocked {
		t.Errorf("a hash behind a ! is locked, got %q", got)
	}
}

func TestParseShadowAging(t *testing.T) {
	entries := ParseShadow(read(t, "getent-shadow.txt"))
	alice := entries["alice"].Aging
	if !alice.Known {
		t.Fatal("the aging of a parsed line is known")
	}
	if alice.LastChange != "2026-07-27" {
		t.Errorf("last change = %q, want the date 20661 days after the epoch",
			alice.LastChange)
	}
	if alice.MaxDays != 90 || alice.WarnDays != 7 || alice.Inactive != 30 {
		t.Errorf("aging = %+v", alice)
	}
	if alice.Expires != "2027-03-23" {
		t.Errorf("expires = %q", alice.Expires)
	}
	if alice.NoExpiry() {
		t.Error("a 90 day password does expire")
	}

	root := entries["root"].Aging
	if !root.NoExpiry() {
		t.Error("99999 days is the shadow spelling of never")
	}
	if root.Expires != "" {
		t.Errorf("an empty expiry field is no expiry, got %q", root.Expires)
	}
}

func TestParseChage(t *testing.T) {
	aging := ParseChage(read(t, "chage-l.txt"))
	if !aging.Known {
		t.Fatal("chage -l output is known aging")
	}
	if aging.LastChange != "Aug 01, 2026" || aging.Expires != "Dec 31, 2026" {
		t.Errorf("aging = %+v", aging)
	}
	if aging.MaxDays != 90 || aging.MinDays != 0 || aging.WarnDays != 7 {
		t.Errorf("day counts = %+v", aging)
	}

	never := ParseChage(read(t, "chage-l-never.txt"))
	if never.Expires != "" || never.LastChange != "" {
		t.Errorf("chage's \"never\" is an absence, got %+v", never)
	}
	if !never.NoExpiry() {
		t.Error("99999 days is never")
	}
}

// TestParseLastlog covers both implementations and the case the columns get
// wrong: a user name long enough to push the rest of the line out of its
// fields.
func TestParseLastlog(t *testing.T) {
	for _, fixture := range []string{"lastlog.txt", "lastlog2.txt"} {
		logins := ParseLastlog(read(t, fixture))
		root, ok := logins["root"]
		if !ok || root.When == "" {
			t.Fatalf("%s: root = %+v", fixture, root)
		}
		if root.From != "pts/0" {
			t.Errorf("%s: root logged in from %q, want pts/0", fixture, root.From)
		}
		alice := logins["alice"]
		if alice.From != "pts/1 192.0.2.44" {
			t.Errorf("%s: alice from %q", fixture, alice.From)
		}
	}

	logins := ParseLastlog(read(t, "lastlog.txt"))
	if login, ok := logins["bin"]; !ok || login.When != "" {
		t.Errorf("an account that never logged in is recorded with no date: %+v",
			login)
	}
	if login := logins["verylongusername"]; login.When == "" ||
		login.From != "tty2" {
		t.Errorf("a name longer than the column broke the parse: %+v", login)
	}
}

func TestParseLast(t *testing.T) {
	login, ok := ParseLast(read(t, "last.txt"))
	if !ok {
		t.Fatal("ParseLast found nothing")
	}
	if login.From != "pts/1 192.0.2.44" {
		t.Errorf("from = %q", login.From)
	}
	if login.When == "" {
		t.Errorf("when = %q", login.When)
	}
	if _, ok := ParseLast("\nwtmp begins Sat Aug  1 00:14:02 2026\n"); ok {
		t.Error("a wtmp banner alone is not a login")
	}
}

func TestParseAuthorizedKeys(t *testing.T) {
	keys := ParseAuthorizedKeys(read(t, "authorized_keys"))
	if len(keys) != 3 {
		t.Fatalf("got %d keys, want 3", len(keys))
	}
	if keys[0].Type != "ssh-ed25519" || keys[0].Comment != "alice@laptop" {
		t.Errorf("first key = %+v", keys[0])
	}
	// The line number is what a removal rewrites the file without, so it has
	// to survive the comment and the blank line above.
	if keys[0].Line != 3 {
		t.Errorf("first key is on line %d, want 3", keys[0].Line)
	}
	restricted := keys[2]
	if restricted.Options == "" || restricted.Type != "ssh-ed25519" {
		t.Errorf("a restricted key keeps its options: %+v", restricted)
	}
	if restricted.Comment != "backup@runner" {
		t.Errorf("restricted comment = %q", restricted.Comment)
	}
}

func TestParseFingerprints(t *testing.T) {
	keys := ParseAuthorizedKeys(read(t, "authorized_keys"))
	keys = ParseFingerprints(read(t, "ssh-keygen-l.txt"), keys)
	if keys[0].Fingerprint == "" || keys[0].Bits != 256 {
		t.Errorf("first key = %+v", keys[0])
	}
	if keys[1].Bits != 3072 {
		t.Errorf("the RSA key is 3072 bits, got %d", keys[1].Bits)
	}

	// ssh-keygen skipping a line would misalign every fingerprint after it,
	// so a count that does not match attaches none at all.
	short := ParseFingerprints("256 SHA256:only one alice@laptop (ED25519)",
		ParseAuthorizedKeys(read(t, "authorized_keys")))
	for _, key := range short {
		if key.Fingerprint != "" {
			t.Errorf("a partial ssh-keygen answer must not be zipped on: %+v", key)
		}
	}
}

func TestParseSudoers(t *testing.T) {
	file := ParseSudoers("/etc/sudoers", read(t, "sudoers.txt"))
	if len(file.Entries) != 3 {
		t.Fatalf("got %d rules, want 3: %+v", len(file.Entries), file.Entries)
	}
	if file.Entries[0].Who != "root" || !file.Entries[0].AllCommands {
		t.Errorf("first rule = %+v", file.Entries[0])
	}
	if file.Entries[1].Who != "%wheel" {
		t.Errorf("second rule = %+v", file.Entries[1])
	}
	nopasswd := file.Entries[2]
	if nopasswd.Who != "alice" || !nopasswd.NoPasswd {
		t.Errorf("the NOPASSWD rule = %+v", nopasswd)
	}
	if nopasswd.Line != 9 {
		t.Errorf("the NOPASSWD rule is on line %d, want 9", nopasswd.Line)
	}
	// Defaults, aliases, includes and comments are quoted in Raw and are not
	// rules: a tool that counted them would report sudo access nobody has.
	if file.Raw == "" {
		t.Error("the raw text must be kept for the detail screen")
	}
}

func TestParseSudoList(t *testing.T) {
	rules, noPasswd := ParseSudoList(read(t, "sudo-l.txt"))
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2: %v", len(rules), rules)
	}
	if !noPasswd {
		t.Error("one of the rules is NOPASSWD")
	}
	if rules[0] != "(ALL) ALL" {
		t.Errorf("first rule = %q", rules[0])
	}

	denied, _ := ParseSudoList("Sorry, user carol is not allowed to run sudo on host.")
	if len(denied) != 0 {
		t.Errorf("a refusal is no rules, got %v", denied)
	}
}

func TestParseLoginctl(t *testing.T) {
	sessions := ParseLoginctl(read(t, "loginctl.txt"))
	if len(sessions) != 3 {
		t.Fatalf("got %d sessions, want 3", len(sessions))
	}
	if sessions[0].User != "alice" || sessions[0].TTY != "tty2" ||
		sessions[0].Type != "seat0" {
		t.Errorf("first session = %+v", sessions[0])
	}
	if sessions[1].User != "bob" || sessions[1].TTY != "pts/3" {
		t.Errorf("second session = %+v", sessions[1])
	}
}

func TestParseLoginDefs(t *testing.T) {
	limits := ParseLoginDefs(read(t, "login.defs.txt"))
	if limits.UIDMin != 1000 || limits.UIDMax != 60000 {
		t.Errorf("uid range = %d–%d", limits.UIDMin, limits.UIDMax)
	}
	if limits.SysUIDMax != 999 || limits.PassMaxDays != 99999 {
		t.Errorf("limits = %+v", limits)
	}
	if !limits.Human(1000) || limits.Human(999) {
		t.Error("the human range is what tells a person from a service")
	}

	// A machine with no login.defs falls back to the compiled-in values
	// rather than to zero, which would make every account a system account.
	fallback := ParseLoginDefs("")
	if fallback.UIDMin != 1000 {
		t.Errorf("fallback = %+v", fallback)
	}
}

func TestParseShells(t *testing.T) {
	shells := ParseShells(read(t, "shells.txt"))
	want := []string{"/bin/sh", "/bin/bash", "/usr/bin/zsh", "/bin/zsh"}
	if len(shells) != len(want) {
		t.Fatalf("got %v, want %v", shells, want)
	}
	for i := range want {
		if shells[i] != want[i] {
			t.Errorf("shell %d = %q, want %q", i, shells[i], want[i])
		}
	}
}

func TestParseSemanageLogin(t *testing.T) {
	mapping := ParseSemanageLogin(read(t, "semanage-login.txt"))
	if mapping["alice"] != "staff_u" {
		t.Errorf("alice maps to %q, want staff_u", mapping["alice"])
	}
	if mapping["__default__"] != "unconfined_u" {
		t.Errorf("the default mapping = %q", mapping["__default__"])
	}
	if _, ok := mapping["Login"]; ok {
		t.Error("the header row is not a mapping")
	}
}

// TestFlagsFindWhatMatters is the "failed first" contract: the accounts that
// go to the top of the list, and the ones that must not.
func TestFlagsFindWhatMatters(t *testing.T) {
	limits := accounts.DefaultLimits()
	tests := []struct {
		name     string
		user     accounts.User
		severity string
	}{
		{
			name: "a second uid 0",
			user: accounts.User{Name: "toolbox", UID: 0, Shell: "/bin/bash",
				Password: accounts.PasswordUsable},
			severity: accounts.SeverityCritical,
		},
		{
			name: "an empty password",
			user: accounts.User{Name: "bob", UID: 1001, Shell: "/bin/bash",
				Password: accounts.PasswordEmpty},
			severity: accounts.SeverityCritical,
		},
		{
			name: "a service account with a shell",
			user: accounts.User{Name: "postgres", UID: 26, Shell: "/bin/bash",
				Password: accounts.PasswordNever},
			severity: accounts.SeverityWarning,
		},
		{
			name: "a password that never expires",
			user: accounts.User{Name: "alice", UID: 1000, Shell: "/bin/bash",
				Password: accounts.PasswordUsable,
				Aging:    accounts.Aging{Known: true, MaxDays: 99999}},
			severity: accounts.SeverityNotice,
		},
	}
	for _, test := range tests {
		flags := Flags(test.user, limits)
		if len(flags) == 0 {
			t.Errorf("%s: nothing was flagged", test.name)
			continue
		}
		if flags[0].Severity != test.severity {
			t.Errorf("%s: severity %q, want %q",
				test.name, flags[0].Severity, test.severity)
		}
		if flags[0].Reason == "" {
			t.Errorf("%s: a flag with no reason is not worth showing", test.name)
		}
	}
}

// TestFlagsStayQuiet is the other half: the tool must not cry wolf about root,
// about a service account that cannot log in, or about a password state it
// could not read.
func TestFlagsStayQuiet(t *testing.T) {
	limits := accounts.DefaultLimits()
	quiet := []accounts.User{
		{Name: "root", UID: 0, Shell: "/bin/bash",
			Password: accounts.PasswordUsable},
		{Name: "nginx", UID: 978, Shell: "/usr/sbin/nologin",
			Password: accounts.PasswordNever},
		{Name: "sync", UID: 5, Shell: "/bin/sync",
			Password: accounts.PasswordNever},
		// Without /etc/shadow the password state is unknown, and an unknown
		// state is not a finding.
		{Name: "carol", UID: 1002, Shell: "/bin/bash",
			Password: accounts.PasswordUnknown},
	}
	for _, user := range quiet {
		if flags := Flags(user, limits); len(flags) != 0 {
			t.Errorf("%s was flagged for %+v", user.Name, flags)
		}
	}
}

// TestSortUsersPutsFindingsFirst is what the list screen depends on: the worst
// finding at the top, everything else by UID.
func TestSortUsersPutsFindingsFirst(t *testing.T) {
	limits := accounts.DefaultLimits()
	users := ParsePasswd(read(t, "getent-passwd.txt"))
	entries := ParseShadow(read(t, "getent-shadow.txt"))
	for i := range users {
		if entry, ok := entries[users[i].Name]; ok {
			users[i].Password, users[i].Aging = entry.State, entry.Aging
		}
		users[i].System = !limits.Human(users[i].UID)
		users[i].Flags = Flags(users[i], limits)
	}
	accounts.SortUsers(users)

	if users[0].Name != "toolbox" {
		t.Errorf("first account = %s, want the second uid 0", users[0].Name)
	}
	if users[1].Name != "bob" {
		t.Errorf("second account = %s, want the empty password", users[1].Name)
	}
	// Everything unflagged follows, ordered by UID.
	last := -1
	for _, user := range users {
		if user.Flagged() {
			continue
		}
		if user.UID < last {
			t.Errorf("unflagged accounts are out of UID order at %s", user.Name)
		}
		last = user.UID
	}
}
