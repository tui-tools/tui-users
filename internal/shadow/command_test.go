package shadow

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-users/internal/accounts"
)

// alice is the account the write path is built against.
var alice = accounts.User{
	Name: "alice", UID: 1000, GID: 1000, PrimaryGroup: "alice",
	Home: "/home/alice", Shell: "/bin/bash",
}

func TestBuildCreateUser(t *testing.T) {
	tests := []struct {
		name string
		spec accounts.NewUser
		want string
	}{
		{
			name: "a person",
			spec: accounts.NewUser{Name: "alice", Shell: "/bin/bash",
				Comment: "Alice Moreira", Groups: []string{"wheel", "docker"},
				CreateHome: true},
			want: "useradd -m -s /bin/bash -c Alice Moreira -G wheel,docker alice",
		},
		{
			name: "a service",
			spec: accounts.NewUser{Name: "worker", Shell: "/usr/sbin/nologin",
				System: true},
			want: "useradd -r -s /usr/sbin/nologin worker",
		},
		{
			name: "the machine's default shell",
			spec: accounts.NewUser{Name: "bob", CreateHome: true},
			want: "useradd -m bob",
		},
	}
	for _, test := range tests {
		commands, err := BuildCreateUser(test.spec)
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		if len(commands) != 1 {
			t.Fatalf("%s: %d commands, want 1", test.name, len(commands))
		}
		if got := commands[0].String(); got != test.want {
			t.Errorf("%s: argv %q, want %q", test.name, got, test.want)
		}
		if commands[0].Description == "" {
			t.Errorf("%s: a command with no description cannot be confirmed",
				test.name)
		}
	}
}

func TestBuildCreateUserRejects(t *testing.T) {
	// The name and the shell reach an argv run as root, so anything that is
	// not a name or an absolute path is refused before a command exists.
	tests := []struct {
		name string
		spec accounts.NewUser
	}{
		{"an empty name", accounts.NewUser{}},
		{"a shell command", accounts.NewUser{Name: "alice; reboot"}},
		{"an upper case name", accounts.NewUser{Name: "Alice"}},
		{"a relative shell", accounts.NewUser{Name: "alice", Shell: "bash"}},
		{"a shell with a space", accounts.NewUser{Name: "alice",
			Shell: "/bin/bash -c evil"}},
		{"a colon in the comment", accounts.NewUser{Name: "alice",
			Comment: "root:x:0:0"}},
		{"a group that is not a name", accounts.NewUser{Name: "alice",
			Groups: []string{"wheel docker"}}},
		{"a system account with a home", accounts.NewUser{Name: "worker",
			System: true, CreateHome: true}},
	}
	for _, test := range tests {
		if _, err := BuildCreateUser(test.spec); err == nil {
			t.Errorf("%s: BuildCreateUser accepted %+v", test.name, test.spec)
		}
	}
}

func TestBuildDeleteUser(t *testing.T) {
	keep, err := BuildDeleteUser("alice", false)
	if err != nil {
		t.Fatalf("BuildDeleteUser: %v", err)
	}
	if got := keep.String(); got != "userdel alice" {
		t.Errorf("argv %q", got)
	}
	if !strings.Contains(keep.Description, "keeping its home") {
		t.Errorf("description = %q", keep.Description)
	}

	remove, err := BuildDeleteUser("alice", true)
	if err != nil {
		t.Fatalf("BuildDeleteUser: %v", err)
	}
	if got := remove.String(); got != "userdel -r alice" {
		t.Errorf("argv %q", got)
	}
	if !remove.Destructive {
		t.Error("deleting an account is a destructive change")
	}

	if _, err := BuildDeleteUser("root", true); err == nil {
		t.Error("root cannot be deleted")
	}
}

func TestBuildLock(t *testing.T) {
	lock, err := BuildLock("alice", true)
	if err != nil {
		t.Fatalf("BuildLock: %v", err)
	}
	if got := lock.String(); got != "usermod -L alice" {
		t.Errorf("argv %q", got)
	}
	unlock, err := BuildLock("alice", false)
	if err != nil {
		t.Fatalf("BuildLock: %v", err)
	}
	if got := unlock.String(); got != "usermod -U alice" {
		t.Errorf("argv %q", got)
	}
	if unlock.Destructive {
		t.Error("unlocking is not the destructive half")
	}
}

// TestBuildSetPasswordKeepsTheSecretOffTheCommandLine is the reason
// Command.Stdin exists: a password on an argv is readable in `ps` by every
// user on the machine, and this tool puts the argv on screen as well.
func TestBuildSetPasswordKeepsTheSecretOffTheCommandLine(t *testing.T) {
	cmd, err := BuildSetPassword("alice", "correct horse battery")
	if err != nil {
		t.Fatalf("BuildSetPassword: %v", err)
	}
	if got := cmd.String(); got != "chpasswd" {
		t.Fatalf("argv %q, want chpasswd alone", got)
	}
	if strings.Contains(cmd.String(), "correct") ||
		strings.Contains(cmd.Description, "correct") {
		t.Errorf("the password leaked into %q / %q", cmd.String(), cmd.Description)
	}
	if cmd.Stdin != "alice:correct horse battery\n" {
		t.Errorf("stdin = %q", cmd.Stdin)
	}

	// A colon or a newline would rewrite which account chpasswd is told about.
	for _, bad := range []string{"", "with:colon", "with\nnewline"} {
		if _, err := BuildSetPassword("alice", bad); err == nil {
			t.Errorf("BuildSetPassword accepted %q", bad)
		}
	}
}

func TestBuildGroupMembership(t *testing.T) {
	add, err := BuildGroupMembership(true, "alice", "wheel")
	if err != nil {
		t.Fatalf("BuildGroupMembership: %v", err)
	}
	if got := add.String(); got != "gpasswd -a alice wheel" {
		t.Errorf("argv %q", got)
	}
	remove, err := BuildGroupMembership(false, "alice", "wheel")
	if err != nil {
		t.Fatalf("BuildGroupMembership: %v", err)
	}
	if got := remove.String(); got != "gpasswd -d alice wheel" {
		t.Errorf("argv %q", got)
	}
	for _, bad := range []string{"wheel docker", "-x", ""} {
		if _, err := BuildGroupMembership(true, "alice", bad); err == nil {
			t.Errorf("BuildGroupMembership accepted the group %q", bad)
		}
	}
}

// TestBuildSudoNamesTheGroup covers the wrapper's whole reason to exist: the
// argv is the membership one, and the description says what it means.
func TestBuildSudoNamesTheGroup(t *testing.T) {
	grant, err := BuildSudo(true, "alice", "wheel")
	if err != nil {
		t.Fatalf("BuildSudo: %v", err)
	}
	if got := grant.String(); got != "gpasswd -a alice wheel" {
		t.Errorf("argv %q", got)
	}
	if !strings.Contains(grant.Description, "Grant sudo to alice") ||
		!strings.Contains(grant.Description, "wheel") {
		t.Errorf("description = %q", grant.Description)
	}

	// On Debian the same key means the same thing through another group, and
	// the confirm dialog has to say which one.
	revoke, err := BuildSudo(false, "alice", "sudo")
	if err != nil {
		t.Fatalf("BuildSudo: %v", err)
	}
	if got := revoke.String(); got != "gpasswd -d alice sudo" {
		t.Errorf("argv %q", got)
	}
	if !strings.Contains(revoke.Description, "Revoke sudo from alice") ||
		!strings.Contains(revoke.Description, "the group sudo") {
		t.Errorf("description = %q", revoke.Description)
	}
	if !revoke.Destructive {
		t.Error("taking sudo away is a destructive change")
	}

	for _, bad := range []string{"wheel docker", "-x", ""} {
		if _, err := BuildSudo(true, "alice", bad); err == nil {
			t.Errorf("BuildSudo accepted the group %q", bad)
		}
	}
	if _, err := BuildSudo(true, "Alice; reboot", "wheel"); err == nil {
		t.Error("BuildSudo accepted a name that is not one")
	}
}

func TestBuildCreateGroup(t *testing.T) {
	auto, err := BuildCreateGroup(accounts.NewGroup{Name: "developers"})
	if err != nil {
		t.Fatalf("BuildCreateGroup: %v", err)
	}
	if got := auto.String(); got != "groupadd developers" {
		t.Errorf("argv %q", got)
	}
	if auto.Description == "" {
		t.Error("a command with no description cannot be confirmed")
	}

	chosen, err := BuildCreateGroup(accounts.NewGroup{Name: "developers",
		GID: "1500"})
	if err != nil {
		t.Fatalf("BuildCreateGroup: %v", err)
	}
	if got := chosen.String(); got != "groupadd -g 1500 developers" {
		t.Errorf("argv %q", got)
	}
	// A padded number reaches groupadd as the number it means.
	padded, err := BuildCreateGroup(accounts.NewGroup{Name: "developers",
		GID: " 007 "})
	if err != nil {
		t.Fatalf("BuildCreateGroup: %v", err)
	}
	if got := padded.String(); got != "groupadd -g 7 developers" {
		t.Errorf("argv %q", got)
	}
}

func TestBuildCreateGroupRejects(t *testing.T) {
	// The name and the GID both end up in an argv run as root.
	for _, spec := range []accounts.NewGroup{
		{},
		{Name: "Developers"},
		{Name: "dev; reboot"},
		{Name: "dev team"},
		{Name: "developers", GID: "-1"},
		{Name: "developers", GID: "1e3"},
		{Name: "developers", GID: "99999999"},
		{Name: "developers", GID: "0x10"},
	} {
		if _, err := BuildCreateGroup(spec); err == nil {
			t.Errorf("BuildCreateGroup accepted %+v", spec)
		}
	}
}

func TestBuildDeleteGroup(t *testing.T) {
	empty := accounts.Group{Name: "developers", GID: 1500}
	cmd, err := BuildDeleteGroup(empty, false)
	if err != nil {
		t.Fatalf("BuildDeleteGroup: %v", err)
	}
	if got := cmd.String(); got != "groupdel developers" {
		t.Errorf("argv %q", got)
	}
	if !cmd.Destructive {
		t.Error("deleting a group is a destructive change")
	}
}

// TestBuildDeleteGroupRefusals is the whole safety of the action: a group that
// still means something to an account is never deleted, and a package's group
// needs the extra answer.
func TestBuildDeleteGroupRefusals(t *testing.T) {
	tests := []struct {
		name  string
		group accounts.Group
		want  string
	}{
		{
			name: "a supplementary member",
			group: accounts.Group{Name: "docker", GID: 1500,
				Members: []string{"bob"}},
			want: "member",
		},
		{
			name: "somebody's primary group",
			group: accounts.Group{Name: "alice", GID: 1000,
				Primary: []string{"alice"}},
			want: "primary group",
		},
		{
			name:  "a system group",
			group: accounts.Group{Name: "wheel", GID: 10, System: true},
			want:  "system group",
		},
		{
			name:  "a name that is not one",
			group: accounts.Group{Name: "wheel; reboot"},
			want:  "not a valid group name",
		},
	}
	for _, test := range tests {
		_, err := BuildDeleteGroup(test.group, false)
		if err == nil {
			t.Errorf("%s: BuildDeleteGroup accepted it", test.name)
			continue
		}
		if !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: error = %q, want it to mention %q",
				test.name, err, test.want)
		}
	}

	// allowSystem is the typed confirmation, and it lifts that refusal only.
	system := accounts.Group{Name: "wheel", GID: 10, System: true}
	if _, err := BuildDeleteGroup(system, true); err != nil {
		t.Errorf("BuildDeleteGroup refused a confirmed system group: %v", err)
	}
	populated := accounts.Group{Name: "wheel", GID: 10, System: true,
		Members: []string{"alice"}}
	if _, err := BuildDeleteGroup(populated, true); err == nil {
		t.Error("a group with members is refused however it was confirmed")
	}
}

func TestBuildSetShell(t *testing.T) {
	cmd, err := BuildSetShell("alice", "/usr/bin/fish")
	if err != nil {
		t.Fatalf("BuildSetShell: %v", err)
	}
	if got := cmd.String(); got != "usermod -s /usr/bin/fish alice" {
		t.Errorf("argv %q", got)
	}
	for _, bad := range []string{"fish", "/bin/sh; reboot", ""} {
		if _, err := BuildSetShell("alice", bad); err == nil {
			t.Errorf("BuildSetShell accepted %q", bad)
		}
	}
}

func TestBuildSetExpiry(t *testing.T) {
	commands, err := BuildSetExpiry("alice", "2027-01-31", "90")
	if err != nil {
		t.Fatalf("BuildSetExpiry: %v", err)
	}
	if len(commands) != 2 {
		t.Fatalf("got %d commands, want one per answer", len(commands))
	}
	if got := commands[0].String(); got != "chage -E 2027-01-31 alice" {
		t.Errorf("argv %q", got)
	}
	if got := commands[1].String(); got != "chage -M 90 alice" {
		t.Errorf("argv %q", got)
	}

	// "never" is -1 on both, and an empty answer changes nothing rather than
	// silently resetting the policy.
	never, err := BuildSetExpiry("alice", NeverExpires, "")
	if err != nil {
		t.Fatalf("BuildSetExpiry: %v", err)
	}
	if len(never) != 1 || never[0].String() != "chage -E -1 alice" {
		t.Errorf("commands = %v", never)
	}

	for _, test := range [][2]string{
		{"31/01/2027", ""}, {"", "ninety"}, {"", "0"}, {"", ""},
	} {
		if _, err := BuildSetExpiry("alice", test[0], test[1]); err == nil {
			t.Errorf("BuildSetExpiry accepted %q / %q", test[0], test[1])
		}
	}
}

func TestCheckKeyLine(t *testing.T) {
	good := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJk3fixture000000 alice@laptop"
	if err := CheckKeyLine(good); err != nil {
		t.Errorf("CheckKeyLine refused a key: %v", err)
	}
	tests := map[string]string{
		"empty":          "",
		"a private key":  "-----BEGIN OPENSSH PRIVATE KEY-----",
		"a whole file":   good + "\n" + good,
		"a bare comment": "alice@laptop",
		"a shell":        "ssh-ed25519 $(reboot) alice@laptop",
	}
	for name, line := range tests {
		if err := CheckKeyLine(line); err == nil {
			t.Errorf("CheckKeyLine accepted %s", name)
		}
	}
}

// TestKeyCommandsAreOwnedByTheAccount covers the part that is easy to get
// wrong: a file `tee` creates belongs to root, mode 0644, in somebody else's
// home directory.
func TestKeyCommandsAreOwnedByTheAccount(t *testing.T) {
	dir, err := BuildEnsureKeysDir(alice)
	if err != nil {
		t.Fatalf("BuildEnsureKeysDir: %v", err)
	}
	want := "install -d -m 700 -o alice -g alice /home/alice/.ssh"
	if got := dir.String(); got != want {
		t.Errorf("argv %q, want %q", got, want)
	}

	create, err := BuildCreateKeysFile(alice)
	if err != nil {
		t.Fatalf("BuildCreateKeysFile: %v", err)
	}
	want = "install -m 600 -o alice -g alice /dev/null " +
		"/home/alice/.ssh/authorized_keys"
	if got := create.String(); got != want {
		t.Errorf("argv %q, want %q", got, want)
	}

	appendCmd, err := BuildAppendKey(alice,
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJk3fixture000000 alice@laptop")
	if err != nil {
		t.Fatalf("BuildAppendKey: %v", err)
	}
	if got := appendCmd.String(); got != "tee -a /home/alice/.ssh/authorized_keys" {
		t.Errorf("argv %q", got)
	}
	if !strings.HasSuffix(appendCmd.Stdin, "\n") ||
		!strings.HasPrefix(appendCmd.Stdin, "ssh-ed25519 ") {
		t.Errorf("stdin = %q", appendCmd.Stdin)
	}
}

func TestKeyCommandsRefuseAnImpossibleHome(t *testing.T) {
	// The home directory comes from the passwd database, which is as
	// trustworthy as the machine — and the machine is what this tool has to
	// survive being wrong about.
	for _, home := range []string{"", "/", "relative/path", "/home/../etc",
		"/home/with space"} {
		user := alice
		user.Home = home
		if _, err := BuildEnsureKeysDir(user); err == nil {
			t.Errorf("BuildEnsureKeysDir accepted the home %q", home)
		}
		if _, err := BuildInstallKeys(user, "/tmp/x"); err == nil {
			t.Errorf("BuildInstallKeys accepted the home %q", home)
		}
	}
}

func TestWithoutKey(t *testing.T) {
	raw := "# comment\nssh-ed25519 AAAA one@host\nssh-rsa BBBB two@host\n"
	keys := ParseAuthorizedKeys(raw)
	after, ok := WithoutKey(raw, keys[0])
	if !ok {
		t.Fatal("WithoutKey refused a key that is in the file")
	}
	if strings.Contains(after, "one@host") {
		t.Errorf("the key is still there:\n%s", after)
	}
	if !strings.Contains(after, "# comment") ||
		!strings.Contains(after, "two@host") {
		t.Errorf("the rest of the file must survive:\n%s", after)
	}

	// A file that changed under us keeps every key rather than deleting
	// whatever moved into that line.
	moved := keys[0]
	moved.Raw = "ssh-ed25519 CCCC three@host"
	if _, ok := WithoutKey(raw, moved); ok {
		t.Error("WithoutKey rewrote a file that no longer matches what was read")
	}
	if _, ok := WithoutKey(raw, accounts.Key{Line: 99}); ok {
		t.Error("WithoutKey accepted a line past the end of the file")
	}
}

func TestDiff(t *testing.T) {
	before := "ssh-ed25519 AAAA one@host\nssh-rsa BBBB two@host\n"
	after := "ssh-ed25519 AAAA one@host\n"
	diff := Diff("/home/alice/.ssh/authorized_keys", before, after)
	for _, want := range []string{
		"--- /home/alice/.ssh/authorized_keys",
		"+++ /home/alice/.ssh/authorized_keys",
		"-ssh-rsa BBBB two@host",
	} {
		if !strings.Contains(diff, want) {
			t.Errorf("diff is missing %q:\n%s", want, diff)
		}
	}
	if strings.Contains(diff, "-ssh-ed25519") {
		t.Errorf("the diff repeated an unchanged line:\n%s", diff)
	}
	if Diff("/x", "same\n", "same\n") != "" {
		t.Error("an identical file must produce no diff")
	}
	if !strings.Contains(Diff("/x", "", "new\n"), "--- /dev/null") {
		t.Error("a new file diffs against /dev/null")
	}
}

func TestKeysPath(t *testing.T) {
	if got := KeysPath("/home/alice"); got != "/home/alice/.ssh/authorized_keys" {
		t.Errorf("KeysPath = %q", got)
	}
}
