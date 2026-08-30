package shadow

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/tui-tools/tui-kit/runner"
	"github.com/tui-tools/tui-users/internal/accounts"
)

// The sample machine's authorized_keys files. They are what --demo shows on
// the detail screen, and what the add and remove key actions rewrite.
const (
	demoAliceKeys = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJk3demoalicekey0000000000000000000000000 alice@laptop\n" +
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDdemoaliceoldkey00000000000000000 alice@old-desktop\n"
	demoBobKeys = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJk3demobobkey000000000000000000000000000 bob@workstation\n"
)

// demoSudoers is the sample machine's sudo configuration: the distribution's
// own wheel rule, and the passwordless rule a cloud image leaves behind — which
// is exactly the line this tool exists to put in front of somebody.
const (
	demoSudoersMain = `## Allow root to run any commands anywhere
root	ALL=(ALL)	ALL

## Allows people in group wheel to run all commands
%wheel	ALL=(ALL)	ALL
`
	demoSudoersCloud = `# Created by cloud-init v. 24.1 on the first boot
alice ALL=(ALL) NOPASSWD:ALL
`
)

// demoSudoersCloudPath is where that second file lives.
const demoSudoersCloudPath = sudoersDir + "/90-cloud-init-users"

// Fake is an in-memory shadow-utils. It backs --demo and the tests: every key
// works, every command is built and previewed exactly as the real backend
// builds it, and nothing reaches the system.
//
// The commands are recorded rather than run, and a hook applies to the
// in-memory machine the change the real command would have made — so locking
// an account in --demo really does show it locked, and the argv the confirm
// dialog displayed is the argv a test can assert on.
type Fake struct {
	model accounts.Model
	run   *runner.Fake
	// files is the sample machine's filesystem, as far as this tool is
	// concerned: authorized_keys by path, plus the staging paths a pending
	// rewrite was written to.
	files map[string]string
}

// NewFake builds the sample machine: root, two people, a locked account, a
// second account with UID 0, and the service accounts a real machine carries.
func NewFake() *Fake {
	f := &Fake{files: map[string]string{}}
	f.run = &runner.Fake{Prefix: "sudo -n", Hook: f.apply}
	f.reset()
	return f
}

// reset builds the sample state. It is a function rather than a literal so
// --demo starts from the same machine every time, however it was left.
func (f *Fake) reset() {
	limits := accounts.DefaultLimits()
	limits.Source = loginDefsPath

	users := []accounts.User{
		{
			Name: "root", UID: 0, GID: 0, GECOS: "root",
			Home: "/root", Shell: "/bin/bash",
			Password: accounts.PasswordUsable,
			Aging: accounts.Aging{Known: true, LastChange: "2026-06-02",
				MinDays: 0, MaxDays: 99999, WarnDays: 7, Inactive: -1},
			LastLogin: "Fri Aug 28 21:40:11 2026", LastLoginFrom: "tty1",
		},
		{
			Name: "alice", UID: 1000, GID: 1000, GECOS: "Alice Moreira",
			Home: "/home/alice", Shell: "/bin/bash",
			Password: accounts.PasswordUsable,
			Aging: accounts.Aging{Known: true, LastChange: "2026-08-01",
				MinDays: 0, MaxDays: 99999, WarnDays: 7, Inactive: -1},
			LastLogin: "Sat Aug 29 09:02:44 2026", LastLoginFrom: "pts/1",
			KeysPath: "/home/alice/.ssh/authorized_keys",
		},
		{
			Name: "bob", UID: 1001, GID: 1001, GECOS: "Bob Tavares",
			Home: "/home/bob", Shell: "/bin/zsh",
			Password: accounts.PasswordUsable,
			Aging: accounts.Aging{Known: true, LastChange: "2026-03-14",
				MinDays: 0, MaxDays: 90, WarnDays: 7, Inactive: -1,
				Expires: "2026-12-31"},
			LastLogin: "Thu Aug 27 18:11:02 2026", LastLoginFrom: "192.0.2.44",
			KeysPath: "/home/bob/.ssh/authorized_keys",
		},
		{
			Name: "carol", UID: 1002, GECOS: "Carol Nunes (on leave)",
			GID: 1002, Home: "/home/carol", Shell: "/bin/bash",
			Password: accounts.PasswordLocked,
			Aging: accounts.Aging{Known: true, LastChange: "2026-01-09",
				MinDays: 0, MaxDays: 90, WarnDays: 7, Inactive: 30,
				Expires: "2026-09-30"},
			LastLogin: "Mon Jan 12 08:30:00 2026", LastLoginFrom: "pts/0",
		},
		{
			// The finding the demo exists to show: a second UID 0.
			Name: "backup-svc", UID: 0, GID: 0,
			GECOS: "nightly backup", Home: "/var/lib/backup",
			Shell: "/bin/bash", Password: accounts.PasswordUsable,
			Aging: accounts.Aging{Known: true, LastChange: "2025-11-20",
				MinDays: 0, MaxDays: 99999, WarnDays: 7, Inactive: -1},
		},
		{
			Name: "postgres", UID: 26, GID: 26, GECOS: "PostgreSQL Server",
			Home: "/var/lib/pgsql", Shell: "/bin/bash",
			Password: accounts.PasswordNever,
			Aging:    accounts.Aging{Known: true, MaxDays: 99999, MinDays: 0},
		},
		{
			Name: "nginx", UID: 978, GID: 978, GECOS: "Nginx web server",
			Home: "/var/lib/nginx", Shell: "/usr/sbin/nologin",
			Password: accounts.PasswordNever,
			Aging:    accounts.Aging{Known: true, MaxDays: 99999, MinDays: 0},
		},
		{
			Name: "sshd", UID: 74, GID: 74, GECOS: "Privilege-separated SSH",
			Home: "/usr/share/empty.sshd", Shell: "/usr/sbin/nologin",
			Password: accounts.PasswordNever,
			Aging:    accounts.Aging{Known: true, MaxDays: 99999, MinDays: 0},
		},
	}

	groups := []accounts.Group{
		{Name: "root", GID: 0},
		{Name: "sshd", GID: 74},
		{Name: "postgres", GID: 26},
		{Name: "wheel", GID: 10, Members: []string{"alice", "carol"}},
		{Name: "alice", GID: 1000},
		{Name: "bob", GID: 1001},
		{Name: "carol", GID: 1002},
		{Name: "docker", GID: 968, Members: []string{"bob"}},
		{Name: "nginx", GID: 978},
	}

	f.files = map[string]string{
		"/home/alice/.ssh/authorized_keys": demoAliceKeys,
		"/home/bob/.ssh/authorized_keys":   demoBobKeys,
	}

	f.model = accounts.Model{
		Backend:    "shadow-utils",
		Root:       true,
		ShadowRead: true,
		Limits:     limits,
		Users:      users,
		Groups:     groups,
		SELinux:    true,
		Sudoers: []accounts.SudoersFile{
			ParseSudoers(sudoersPath, demoSudoersMain),
			ParseSudoers(demoSudoersCloudPath, demoSudoersCloud),
		},
		Sessions: []accounts.Session{
			{ID: "3", User: "alice", TTY: "tty2", Type: "seat0"},
			{ID: "8", User: "bob", TTY: "pts/3", Remote: "192.0.2.44"},
		},
	}
	f.refresh()
}

// refresh recomputes everything the model derives from its own contents: the
// group links, the SELinux mapping, the flags and the order. The real backend
// does the same at the end of Load, which is what keeps --demo honest after a
// command has been applied.
func (f *Fake) refresh() {
	link(&f.model)
	for i := range f.model.Users {
		user := &f.model.Users[i]
		user.System = !f.model.Limits.Human(user.UID)
		user.Sudo.Groups = sudoGroupsOf(*user, capabilities.SudoGroups)
		user.SELinuxLogin = "unconfined_u"
		if user.System {
			user.SELinuxLogin = "system_u"
		}
		user.Flags = Flags(*user, f.model.Limits)
	}
	accounts.SortUsers(f.model.Users)
	sort.Slice(f.model.Groups, func(i, j int) bool {
		return f.model.Groups[i].GID < f.model.Groups[j].GID
	})
}

// Name identifies the backend. It is the real backend's name, because --demo
// shows what the real one would show.
func (f *Fake) Name() string { return "shadow-utils" }

// Describe says plainly that nothing here is real.
func (f *Fake) Describe() string { return "demo (in-memory sample machine)" }

// Capabilities reports the same capabilities as the real backend, with the
// shells a machine usually has.
func (f *Fake) Capabilities() accounts.Capabilities {
	return Capabilities([]string{"/bin/bash", "/bin/zsh", "/bin/sh",
		"/usr/bin/fish", "/usr/sbin/nologin"})
}

// Preview renders the command line the real backend would run.
func (f *Fake) Preview(cmd accounts.Command) string { return f.run.Preview(cmd) }

// Load returns the sample machine.
func (f *Fake) Load(_ context.Context) (accounts.Model, error) { return f.model, nil }

// LoadUser returns one account of the sample machine, with the per-account
// reads folded in: its keys, its sudo rules and its sessions.
func (f *Fake) LoadUser(_ context.Context, user accounts.User) (accounts.User, error) {
	found, ok := f.model.User(user.Name)
	if !ok {
		return accounts.User{}, fmt.Errorf("no account named %q", user.Name)
	}
	found.Detailed = true
	found.Sessions = f.model.SessionsFor(found.Name)
	if found.Home != "" {
		found.KeysPath = KeysPath(found.Home)
		if raw, ok := f.files[found.KeysPath]; ok {
			found.Keys = fakeFingerprints(ParseAuthorizedKeys(raw))
		}
	}
	found.Sudo.Rules, found.Sudo.NoPasswd = f.sudoRulesFor(found)
	if len(found.Sudo.Rules) == 0 {
		found.Sudo.Note = "sudo grants this account nothing"
	}
	return found, nil
}

// fakeFingerprints gives the sample keys a plausible fingerprint, so the demo
// screen shows what a real one shows without running ssh-keygen.
func fakeFingerprints(keys []accounts.Key) []accounts.Key {
	prints := []string{
		"SHA256:Qm9ndXNGaW5nZXJwcmludEZvclRoZURlbW8x",
		"SHA256:Qm9ndXNGaW5nZXJwcmludEZvclRoZURlbW8y",
		"SHA256:Qm9ndXNGaW5nZXJwcmludEZvclRoZURlbW8z",
	}
	for i := range keys {
		keys[i].Fingerprint = prints[i%len(prints)]
		keys[i].Bits = 256
		if strings.HasPrefix(keys[i].Type, "ssh-rsa") {
			keys[i].Bits = 3072
		}
	}
	return keys
}

// sudoRulesFor answers what `sudo -l -U <user>` would, from the sample
// machine's own sudoers files.
func (f *Fake) sudoRulesFor(user accounts.User) ([]string, bool) {
	var rules []string
	noPasswd := false
	for _, file := range f.model.Sudoers {
		for _, entry := range file.Entries {
			match := entry.Who == user.Name
			if strings.HasPrefix(entry.Who, "%") {
				group := strings.TrimPrefix(entry.Who, "%")
				for _, member := range append(user.Groups, user.PrimaryGroup) {
					if member == group {
						match = true
					}
				}
			}
			if !match {
				continue
			}
			rules = append(rules, entry.Text)
			noPasswd = noPasswd || entry.NoPasswd
		}
	}
	return rules, noPasswd
}

// Run records the command and applies its effect to the sample machine.
func (f *Fake) Run(ctx context.Context, cmd accounts.Command) (string, error) {
	return f.run.Run(ctx, cmd)
}

// Ran exposes the recorded commands, which is what a test asserts on.
func (f *Fake) Ran() []accounts.Command { return f.run.Ran }

// apply is the hook the fake runner calls: it makes to the in-memory machine
// the change the real command would have made, so the demo stays coherent as
// keys are pressed.
func (f *Fake) apply(cmd accounts.Command) (string, error) {
	argv := cmd.Argv
	if len(argv) == 0 {
		return "", nil
	}
	defer f.refresh()

	switch argv[0] {
	case "useradd":
		return f.addUser(argv)
	case "userdel":
		return f.deleteUser(argv)
	case "usermod":
		return f.modifyUser(argv)
	case "chpasswd":
		return f.setPassword(cmd.Stdin)
	case "gpasswd":
		return f.groupMembership(argv)
	case "chage":
		return f.setAging(argv)
	case "install":
		return f.install(argv)
	case "tee":
		return f.appendFile(argv, cmd.Stdin)
	}
	return "", nil
}

// nextUID is the UID useradd would pick: the first free one above the last
// human account.
func (f *Fake) nextUID(system bool) int {
	next := f.model.Limits.UIDMin
	if system {
		next = f.model.Limits.SysUIDMin
	}
	used := map[int]bool{}
	for _, user := range f.model.Users {
		used[user.UID] = true
	}
	for used[next] {
		next++
	}
	return next
}

// addUser applies a useradd.
func (f *Fake) addUser(argv []string) (string, error) {
	spec := accounts.NewUser{Name: argv[len(argv)-1]}
	var groups []string
	for i := 1; i < len(argv)-1; i++ {
		switch argv[i] {
		case "-m":
			spec.CreateHome = true
		case "-r":
			spec.System = true
		case "-s":
			i++
			if i < len(argv) {
				spec.Shell = argv[i]
			}
		case "-c":
			i++
			if i < len(argv) {
				spec.Comment = argv[i]
			}
		case "-G":
			i++
			if i < len(argv) {
				groups = strings.Split(argv[i], ",")
			}
		}
	}
	if _, exists := f.model.User(spec.Name); exists {
		//nolint:staticcheck // ST1005: this is useradd's own message, quoted
		return "", fmt.Errorf("useradd: user '%s' already exists", spec.Name)
	}

	uid := f.nextUID(spec.System)
	shell := spec.Shell
	if shell == "" {
		shell = "/bin/bash"
	}
	home := "/home/" + spec.Name
	f.model.Users = append(f.model.Users, accounts.User{
		Name: spec.Name, UID: uid, GID: uid, GECOS: spec.Comment,
		Home: home, Shell: shell,
		// useradd leaves an account with no usable password at all.
		Password: accounts.PasswordNever,
		Aging:    accounts.Aging{Known: true, MaxDays: 99999, MinDays: 0},
	})
	f.model.Groups = append(f.model.Groups,
		accounts.Group{Name: spec.Name, GID: uid})
	for _, group := range groups {
		f.addMember(spec.Name, group)
	}
	return "", nil
}

// deleteUser applies a userdel.
func (f *Fake) deleteUser(argv []string) (string, error) {
	name := argv[len(argv)-1]
	for _, session := range f.model.Sessions {
		if session.User == name {
			//nolint:staticcheck // ST1005: this is userdel's own message, quoted
			return "", fmt.Errorf(
				"userdel: user %s is currently used by process %s", name, session.ID)
		}
	}
	kept := f.model.Users[:0]
	found := false
	for _, user := range f.model.Users {
		if user.Name == name {
			found = true
			continue
		}
		kept = append(kept, user)
	}
	if !found {
		//nolint:staticcheck // ST1005: this is userdel's own message, quoted
		return "", fmt.Errorf("userdel: user '%s' does not exist", name)
	}
	f.model.Users = kept
	for i := range f.model.Groups {
		f.model.Groups[i].Members = without(f.model.Groups[i].Members, name)
	}
	return "", nil
}

// modifyUser applies a usermod: a lock, an unlock or a shell change.
func (f *Fake) modifyUser(argv []string) (string, error) {
	if len(argv) < 3 {
		return "", fmt.Errorf("usermod: not enough arguments")
	}
	name := argv[len(argv)-1]
	user := f.user(name)
	if user == nil {
		//nolint:staticcheck // ST1005: this is usermod's own message, quoted
		return "", fmt.Errorf("usermod: user '%s' does not exist", name)
	}
	switch argv[1] {
	case "-L":
		user.Password = accounts.PasswordLocked
	case "-U":
		user.Password = accounts.PasswordUsable
	case "-s":
		if len(argv) < 4 {
			return "", fmt.Errorf("usermod: no shell given")
		}
		user.Shell = argv[2]
	}
	return "", nil
}

// setPassword applies a chpasswd, which reads "user:password" from stdin. The
// password itself is discarded here: what the model records is that the
// account now has one.
func (f *Fake) setPassword(stdin string) (string, error) {
	name, _, found := strings.Cut(strings.TrimSpace(stdin), ":")
	if !found {
		return "", fmt.Errorf("chpasswd: line 1: missing new password")
	}
	user := f.user(name)
	if user == nil {
		return "", fmt.Errorf("chpasswd: line 1: user '%s' does not exist", name)
	}
	user.Password = accounts.PasswordUsable
	return "", nil
}

// groupMembership applies a gpasswd -a or -d.
func (f *Fake) groupMembership(argv []string) (string, error) {
	if len(argv) < 4 {
		return "", fmt.Errorf("gpasswd: not enough arguments")
	}
	name, group := argv[2], argv[3]
	if f.user(name) == nil {
		return "", fmt.Errorf("gpasswd: user '%s' does not exist", name)
	}
	if f.group(group) == nil {
		return "", fmt.Errorf("gpasswd: group '%s' does not exist", group)
	}
	if argv[1] == "-a" {
		f.addMember(name, group)
		return "Adding user " + name + " to group " + group, nil
	}
	target := f.group(group)
	target.Members = without(target.Members, name)
	return "Removing user " + name + " from group " + group, nil
}

// setAging applies a chage -E or -M.
func (f *Fake) setAging(argv []string) (string, error) {
	if len(argv) < 4 {
		return "", fmt.Errorf("chage: not enough arguments")
	}
	user := f.user(argv[3])
	if user == nil {
		//nolint:staticcheck // ST1005: this is chage's own message, quoted
		return "", fmt.Errorf("chage: user '%s' does not exist in %s",
			argv[3], "/etc/passwd")
	}
	user.Aging.Known = true
	switch argv[1] {
	case "-E":
		if argv[2] == "-1" {
			user.Aging.Expires = ""
			return "", nil
		}
		user.Aging.Expires = argv[2]
	case "-M":
		if argv[2] == "-1" {
			user.Aging.MaxDays = -1
			return "", nil
		}
		days := intField(argv[2])
		user.Aging.MaxDays = days
	}
	return "", nil
}

// install applies an `install`: either the directory creation, which the
// sample machine has nothing to record, or the copy of a staged file over an
// authorized_keys file.
func (f *Fake) install(argv []string) (string, error) {
	if len(argv) > 1 && argv[1] == "-d" {
		return "", nil
	}
	if len(argv) < 3 {
		return "", fmt.Errorf("install: not enough arguments")
	}
	source, destination := argv[len(argv)-2], argv[len(argv)-1]
	if source == "/dev/null" {
		f.files[destination] = ""
		return "", nil
	}
	content, ok := f.files[source]
	if !ok {
		return "", fmt.Errorf("install: cannot stat '%s'", source)
	}
	f.files[destination] = content
	return "", nil
}

// appendFile applies a `tee -a`: the stdin is appended to the file.
func (f *Fake) appendFile(argv []string, stdin string) (string, error) {
	if len(argv) < 3 {
		return "", fmt.Errorf("tee: no file given")
	}
	destination := argv[2]
	current := f.files[destination]
	if current != "" && !strings.HasSuffix(current, "\n") {
		current += "\n"
	}
	f.files[destination] = current + stdin
	// tee echoes what it wrote, which is what the real one does.
	return strings.TrimSpace(stdin), nil
}

// user returns a pointer to an account of the sample machine.
func (f *Fake) user(name string) *accounts.User {
	for i := range f.model.Users {
		if f.model.Users[i].Name == name {
			return &f.model.Users[i]
		}
	}
	return nil
}

// group returns a pointer to a group of the sample machine.
func (f *Fake) group(name string) *accounts.Group {
	for i := range f.model.Groups {
		if f.model.Groups[i].Name == name {
			return &f.model.Groups[i]
		}
	}
	return nil
}

// addMember adds a user to a group, once.
func (f *Fake) addMember(user, group string) {
	target := f.group(group)
	if target == nil {
		return
	}
	for _, member := range target.Members {
		if member == user {
			return
		}
	}
	target.Members = append(target.Members, user)
}

// without returns a list with one entry removed.
func without(list []string, value string) []string {
	out := make([]string, 0, len(list))
	for _, item := range list {
		if item != value {
			out = append(out, item)
		}
	}
	return out
}

// BuildCreateUser builds the account creation.
func (f *Fake) BuildCreateUser(spec accounts.NewUser) ([]accounts.Command, error) {
	return BuildCreateUser(spec)
}

// BuildDeleteUser removes an account.
func (f *Fake) BuildDeleteUser(name string, removeHome bool) (accounts.Command, error) {
	return BuildDeleteUser(name, removeHome)
}

// BuildLock locks or unlocks an account's password.
func (f *Fake) BuildLock(name string, lock bool) (accounts.Command, error) {
	return BuildLock(name, lock)
}

// BuildSetPassword sets an account's password.
func (f *Fake) BuildSetPassword(name, password string) (accounts.Command, error) {
	return BuildSetPassword(name, password)
}

// BuildGroupMembership adds a user to a group or removes them from it.
func (f *Fake) BuildGroupMembership(add bool, user, group string) (accounts.Command, error) {
	return BuildGroupMembership(add, user, group)
}

// BuildSetShell changes an account's login shell.
func (f *Fake) BuildSetShell(user, shell string) (accounts.Command, error) {
	return BuildSetShell(user, shell)
}

// BuildSetExpiry sets the account expiry and the password lifetime.
func (f *Fake) BuildSetExpiry(user, expires, maxDays string) ([]accounts.Command, error) {
	return BuildSetExpiry(user, expires, maxDays)
}

// BuildAddKey returns the same plan the real backend returns — the same diff,
// and the same commands. --demo writes nothing at all, so the file it appends
// to is a map entry.
func (f *Fake) BuildAddKey(user accounts.User, key string) (accounts.KeyPlan, error) {
	return keyAppendPlan(user, strings.TrimSpace(key), f.files[KeysPath(user.Home)])
}

// BuildRemoveKey rewrites the sample machine's authorized_keys without one key.
func (f *Fake) BuildRemoveKey(user accounts.User, key accounts.Key) (accounts.KeyPlan, error) {
	filePath := KeysPath(user.Home)
	before, ok := f.files[filePath]
	if !ok {
		return accounts.KeyPlan{}, fmt.Errorf("shadow: %s does not exist", filePath)
	}
	after, removed := WithoutKey(before, key)
	if !removed {
		return accounts.KeyPlan{}, fmt.Errorf(
			"shadow: %s no longer holds that key on line %d — reload and try again",
			filePath, key.Line)
	}
	temp := "/tmp/tui-users/" + KeysFile
	f.files[temp] = after
	installCmd, err := BuildInstallKeys(user, temp)
	if err != nil {
		return accounts.KeyPlan{}, err
	}
	return accounts.KeyPlan{
		Path:     filePath,
		Content:  after,
		Diff:     Diff(filePath, before, after),
		TempPath: temp,
		Commands: []accounts.Command{installCmd},
	}, nil
}
