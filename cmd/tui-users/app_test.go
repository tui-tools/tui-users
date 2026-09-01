package main

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-users/internal/accounts"
	"github.com/tui-tools/tui-users/internal/shadow"
)

// The sample machine is the shadow-utils fake, so a test drives exactly the
// backend --demo drives.
var _ = shadow.NewFake

// newTestApp builds an app on the sample machine, sized like a normal terminal
// and already loaded.
func newTestApp(t *testing.T) (*app, *shadow.Fake) {
	t.Helper()
	backend := shadow.NewFake()
	a := newApp(backend, theme.New(), compat.Result{})
	a.width, a.height = 110, 30
	drain(t, a, a.Init())
	return a, backend
}

// drain runs a tea.Cmd and feeds its message back into the model, which is
// what the Bubble Tea runtime does. It is how a test exercises a load.
func drain(t *testing.T, a *app, cmd tea.Cmd) {
	t.Helper()
	for range 4 {
		if cmd == nil {
			return
		}
		msg := cmd()
		if msg == nil {
			return
		}
		_, cmd = a.Update(msg)
	}
}

// press sends one key and returns the command it produced.
func press(a *app, key string) tea.Cmd {
	var msg tea.KeyMsg
	switch key {
	case "enter":
		msg = tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		msg = tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		msg = tea.KeyMsg{Type: tea.KeyTab}
	default:
		msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
	}
	_, cmd := a.Update(msg)
	return cmd
}

// selectUser moves the cursor to an account by name.
func selectUser(t *testing.T, a *app, name string) {
	t.Helper()
	for i, user := range a.visibleUsers {
		if user.Name == name {
			a.users.cursor = i
			return
		}
	}
	t.Fatalf("no account named %q on the sample machine", name)
}

// openDetailFor opens the detail screen of one account, which is where the
// per-account reads land.
func openDetailFor(t *testing.T, a *app, name string) {
	t.Helper()
	selectUser(t, a, name)
	drain(t, a, press(a, "enter"))
	if a.mode != modeUserDetail {
		t.Fatalf("enter did not open the detail screen of %s", name)
	}
}

func TestLoadsTheSampleMachine(t *testing.T) {
	a, _ := newTestApp(t)
	if len(a.visibleUsers) != 8 {
		t.Fatalf("got %d accounts, want 8", len(a.visibleUsers))
	}
	if len(a.model.Groups) != 9 {
		t.Errorf("got %d groups, want 9", len(a.model.Groups))
	}
	// Findings first: the second uid 0 is the top row.
	if a.visibleUsers[0].Name != "backup-svc" {
		t.Errorf("first row = %s, want the account with uid 0",
			a.visibleUsers[0].Name)
	}
	view := a.View()
	for _, want := range []string{"alice", "backup-svc", "nopasswd"} {
		if !strings.Contains(view, want) {
			t.Errorf("the first frame is missing %q", want)
		}
	}
}

// TestActionsPreviewExactlyWhatTheyRun is the family's central promise, as a
// test: for every action, the command line in the confirm dialog is the
// command line the backend is then asked to run.
func TestActionsPreviewExactlyWhatTheyRun(t *testing.T) {
	tests := []struct {
		name string
		user string
		// keys are pressed in order; a nil setup means no dialog to fill in.
		keys  []string
		setup func(a *app)
		want  string
	}{
		{
			name: "lock", user: "alice", keys: []string{"l"},
			want: "sudo -n usermod -L alice",
		},
		{
			name: "unlock", user: "carol", keys: []string{"l"},
			want: "sudo -n usermod -U carol",
		},
		{
			name: "change the shell", user: "alice",
			keys:  []string{"s"},
			setup: func(a *app) { a.picker.Cursor = 1 },
			want:  "sudo -n usermod -s /bin/zsh alice",
		},
	}
	for _, test := range tests {
		a, backend := newTestApp(t)
		selectUser(t, a, test.user)
		for _, key := range test.keys {
			drain(t, a, press(a, key))
		}
		if test.setup != nil {
			test.setup(a)
			drain(t, a, press(a, "enter"))
		}
		if a.mode != modeConfirm {
			t.Fatalf("%s: no confirm dialog opened (status: %s)",
				test.name, a.status)
		}
		if a.confirm.Command != test.want {
			t.Errorf("%s: previewed %q, want %q",
				test.name, a.confirm.Command, test.want)
		}

		drain(t, a, press(a, "y"))
		ran := backend.Ran()
		if len(ran) != 1 {
			t.Fatalf("%s: ran %d commands, want 1", test.name, len(ran))
		}
		if got := backend.Preview(ran[0]); got != test.want {
			t.Errorf("%s: ran %q, want the previewed %q", test.name, got, test.want)
		}
	}
}

// TestSettingAPasswordNeverShowsIt is the reason the kit runner grew a Stdin
// field: the value must not reach the argv, the preview, the dialog body or
// the status line.
func TestSettingAPasswordNeverShowsIt(t *testing.T) {
	const secret = "correct-horse-battery"
	a, backend := newTestApp(t)
	selectUser(t, a, "alice")

	drain(t, a, press(a, "p"))
	if a.mode != modeInput {
		t.Fatalf("p did not open the password prompt (status: %s)", a.status)
	}
	a.input.Model.SetValue(secret)
	drain(t, a, press(a, "enter"))

	if a.mode != modeConfirm {
		t.Fatalf("the prompt did not open a confirm dialog (status: %s)", a.status)
	}
	if a.confirm.Command != "sudo -n chpasswd" {
		t.Errorf("previewed %q, want chpasswd alone", a.confirm.Command)
	}
	for name, text := range map[string]string{
		"the preview":     a.confirm.Command,
		"the dialog body": a.confirm.Body,
		"the title":       a.confirm.Title,
		"the frame":       a.View(),
	} {
		if strings.Contains(text, secret) {
			t.Errorf("the password leaked into %s", name)
		}
	}

	drain(t, a, press(a, "y"))
	if strings.Contains(a.status, secret) {
		t.Errorf("the password leaked into the status line: %s", a.status)
	}
	ran := backend.Ran()
	if len(ran) != 1 || ran[0].String() != "chpasswd" {
		t.Fatalf("ran %v", ran)
	}
	// It does have to reach the command's stdin, or nothing was set.
	if ran[0].Stdin != "alice:"+secret+"\n" {
		t.Errorf("stdin = %q", ran[0].Stdin)
	}
}

func TestAddingAGroupPreviewsGpasswd(t *testing.T) {
	a, backend := newTestApp(t)
	selectUser(t, a, "bob")
	drain(t, a, press(a, "a"))
	if a.mode != modePicker {
		t.Fatalf("a did not open the group picker (status: %s)", a.status)
	}
	// The picker offers only the groups the account is not already in.
	for _, option := range a.picker.Options {
		if option == "bob" || option == "docker" {
			t.Errorf("the picker offers a group bob is already in: %s", option)
		}
	}
	chosen := a.picker.Selected()
	drain(t, a, press(a, "enter"))

	want := "sudo -n gpasswd -a bob " + chosen
	if a.confirm.Command != want {
		t.Fatalf("previewed %q, want %q", a.confirm.Command, want)
	}
	drain(t, a, press(a, "y"))
	if got := backend.Preview(backend.Ran()[0]); got != want {
		t.Errorf("ran %q, want %q", got, want)
	}
}

// TestDeletingRefusesAnAccountThatIsLoggedIn covers the check userdel would
// make anyway, made before the command is even built so the reason is on
// screen instead of in an exit code.
func TestDeletingRefusesAnAccountThatIsLoggedIn(t *testing.T) {
	a, backend := newTestApp(t)
	selectUser(t, a, "alice")
	drain(t, a, press(a, "D"))
	if a.mode == modePicker || a.mode == modeConfirm {
		t.Fatal("a dialog opened for an account with an open session")
	}
	if !strings.Contains(a.status, "logged in") {
		t.Errorf("status = %q, want the reason", a.status)
	}
	if len(backend.Ran()) != 0 {
		t.Error("a command ran against an account that is logged in")
	}
}

func TestDeletingOffersBothKinds(t *testing.T) {
	a, backend := newTestApp(t)
	selectUser(t, a, "carol")
	drain(t, a, press(a, "D"))
	if a.mode != modePicker {
		t.Fatalf("D did not open the delete picker (status: %s)", a.status)
	}
	if len(a.picker.Options) != 2 {
		t.Fatalf("the picker offers %v", a.picker.Options)
	}
	// The default is the one that cannot destroy anything.
	if a.picker.Selected() != deleteKeepHome {
		t.Errorf("the picker starts on %q", a.picker.Selected())
	}
	a.picker.Cursor = 1
	drain(t, a, press(a, "enter"))

	want := "sudo -n userdel -r carol"
	if a.confirm.Command != want {
		t.Fatalf("previewed %q, want %q", a.confirm.Command, want)
	}
	if !strings.Contains(a.confirm.Body, "home directory") {
		t.Errorf("the dialog does not say what happens to the home: %q",
			a.confirm.Body)
	}
	drain(t, a, press(a, "y"))
	if got := backend.Preview(backend.Ran()[0]); got != want {
		t.Errorf("ran %q, want %q", got, want)
	}
}

// TestAddingAKeyShowsADiffAndTheCommands covers the one action that is more
// than a single command: the directory, then the append, both on screen before
// either runs.
func TestAddingAKeyShowsADiffAndTheCommands(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINewKeyForTheTest0000 alice@new"
	a, backend := newTestApp(t)
	openDetailFor(t, a, "alice")

	drain(t, a, press(a, "K"))
	if a.mode != modePicker {
		t.Fatalf("K did not open the keys picker (status: %s)", a.status)
	}
	drain(t, a, press(a, "enter"))
	if a.mode != modeInput {
		t.Fatalf("the picker did not open the paste prompt (status: %s)", a.status)
	}
	a.input.Model.SetValue(key)
	drain(t, a, press(a, "enter"))

	if a.mode != modeConfirm {
		t.Fatalf("no confirm dialog (status: %s)", a.status)
	}
	if !strings.Contains(a.confirm.Body, "+"+key) {
		t.Errorf("the dialog does not show the added line:\n%s", a.confirm.Body)
	}
	lines := strings.Split(a.confirm.Command, "\n")
	if len(lines) != 2 {
		t.Fatalf("previewed %d command lines, want the install and the append:\n%s",
			len(lines), a.confirm.Command)
	}
	if !strings.Contains(lines[0], "install -d -m 700 -o alice") ||
		!strings.Contains(lines[1], "tee -a /home/alice/.ssh/authorized_keys") {
		t.Errorf("previewed commands = %q", a.confirm.Command)
	}

	drain(t, a, press(a, "y"))
	ran := backend.Ran()
	if len(ran) != 2 {
		t.Fatalf("ran %d commands, want 2", len(ran))
	}
	// The key travels on stdin, so it is in neither argv.
	for _, cmd := range ran {
		if strings.Contains(cmd.String(), "AAAAC3") {
			t.Errorf("the key ended up in an argv: %s", cmd.String())
		}
	}
	if ran[1].Stdin != key+"\n" {
		t.Errorf("stdin = %q", ran[1].Stdin)
	}
}

func TestRemovingAKeyRewritesTheFile(t *testing.T) {
	a, backend := newTestApp(t)
	openDetailFor(t, a, "alice")
	if len(a.detail.Keys) != 2 {
		t.Fatalf("alice has %d keys on the sample machine", len(a.detail.Keys))
	}

	drain(t, a, press(a, "K"))
	a.picker.Cursor = 1 // the first key, after "add a key…"
	drain(t, a, press(a, "enter"))

	if a.mode != modeConfirm {
		t.Fatalf("no confirm dialog (status: %s)", a.status)
	}
	if !strings.Contains(a.confirm.Body, "-ssh-ed25519") {
		t.Errorf("the dialog does not show the key going:\n%s", a.confirm.Body)
	}
	if !strings.Contains(a.confirm.Command, "install -m 600 -o alice -g alice") {
		t.Errorf("previewed %q", a.confirm.Command)
	}

	drain(t, a, press(a, "y"))
	if len(backend.Ran()) != 1 {
		t.Fatalf("ran %v", backend.Ran())
	}
	// The demo machine applies the command, so the key is really gone.
	openDetailFor(t, a, "alice")
	if len(a.detail.Keys) != 1 {
		t.Errorf("alice still has %d keys", len(a.detail.Keys))
	}
}

func TestCancellingRunsNothing(t *testing.T) {
	a, backend := newTestApp(t)
	selectUser(t, a, "alice")
	drain(t, a, press(a, "l"))
	drain(t, a, press(a, "n"))

	if len(backend.Ran()) != 0 {
		t.Errorf("answering no ran %d commands", len(backend.Ran()))
	}
	if a.status != "cancelled" {
		t.Errorf("status = %q, want cancelled", a.status)
	}
}

func TestDetailScreenShowsTheWholeAccount(t *testing.T) {
	a, _ := newTestApp(t)
	openDetailFor(t, a, "alice")

	view := strings.Join(a.userDetailLines(), "\n")
	for _, want := range []string{
		"Account alice", "primary group  alice", "wheel",
		"human account", "Authorized keys", "alice@laptop", "SHA256:",
		"sudo", "NOPASSWD", "Sessions", "session 3",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("the detail screen is missing %q", want)
		}
	}

	drain(t, a, press(a, "esc"))
	if a.mode != modeUsers {
		t.Errorf("esc did not return to the accounts list")
	}
}

func TestTabCyclesTheThreeScreens(t *testing.T) {
	a, _ := newTestApp(t)
	for _, want := range []mode{modeGroups, modeSudoers, modeUsers} {
		drain(t, a, press(a, "tab"))
		if a.mode != want {
			t.Fatalf("tab went to %v, want %v", a.mode, want)
		}
	}
	// Each screen keeps its own cursor, so coming back lands where it was.
	a.users.cursor = 3
	drain(t, a, press(a, "tab"))
	drain(t, a, press(a, "tab"))
	drain(t, a, press(a, "tab"))
	if a.users.cursor != 3 {
		t.Errorf("the accounts cursor moved to %d", a.users.cursor)
	}
}

func TestGroupsScreenShowsPrimaryMembers(t *testing.T) {
	a, _ := newTestApp(t)
	drain(t, a, press(a, "tab"))
	for i, group := range a.visibleGroups {
		if group.Name == "alice" {
			a.groups.cursor = i
		}
	}
	drain(t, a, press(a, "enter"))
	if a.mode != modeGroupDetail {
		t.Fatalf("enter did not open the group")
	}
	view := strings.Join(a.groupDetailLines(), "\n")
	// alice's own group lists nobody in /etc/group, and the account whose
	// primary group it is has to show up anyway.
	if !strings.Contains(view, "alice  primary group of this account") {
		t.Errorf("the group screen is missing its primary member:\n%s", view)
	}
}

func TestFilterMatchesEveryColumn(t *testing.T) {
	a, _ := newTestApp(t)
	for _, test := range []struct {
		needle string
		want   int
	}{
		{"alice", 1},
		{"1000", 1},
		{"nologin", 2},
		{"locked", 1},
		{"nothing here", 0},
	} {
		a.filter = test.needle
		a.applyFilter()
		if len(a.visibleUsers) != test.want {
			t.Errorf("filter %q matched %d accounts, want %d",
				test.needle, len(a.visibleUsers), test.want)
		}
	}
}

// TestRendersAtEveryWidth is the responsive contract: from a narrow pane to a
// wide screen, no frame may wrap, because a wrapped row desynchronises Bubble
// Tea's line accounting and every frame after it lands in the wrong place.
func TestRendersAtEveryWidth(t *testing.T) {
	for width := 40; width <= 200; width += 4 {
		a, _ := newTestApp(t)
		a.width, a.height = width, 24
		a.clampCursor()

		screens := map[string]func(){
			"users":   func() { a.mode = modeUsers },
			"groups":  func() { a.mode = modeGroups },
			"sudoers": func() { a.mode = modeSudoers },
			"detail": func() {
				a.mode = modeUserDetail
				a.detail = a.visibleUsers[0]
			},
			"group detail": func() {
				a.mode = modeGroupDetail
				a.group = a.visibleGroups[0]
			},
			"help": func() { a.mode = modeHelp },
			"create": func() {
				a.mode = modeForm
				a.form = newCreateForm(a.caps)
			},
			"expiry": func() {
				a.mode = modeForm
				a.form = newExpiryForm(a.visibleUsers[0])
			},
			"new group": func() {
				a.mode = modeForm
				a.form = newGroupForm()
			},
		}
		for name, setup := range screens {
			setup()
			for i, line := range strings.Split(a.View(), "\n") {
				if got := lineWidth(line); got > width {
					t.Fatalf("%s at %d cols: line %d is %d cells wide",
						name, width, i, got)
				}
			}
		}
	}
}

// lineWidth measures a rendered line, ignoring the ANSI escapes the theme adds.
func lineWidth(line string) int {
	width, inEscape := 0, false
	for _, r := range line {
		switch {
		case r == 0x1b:
			inEscape = true
		case inEscape && (r == 'm' || r == 'K' || r == 'H'):
			inEscape = false
		case inEscape:
		default:
			width++
		}
	}
	return width
}

func TestBusyStateSwallowsInput(t *testing.T) {
	a, backend := newTestApp(t)
	selectUser(t, a, "alice")
	a.busy = true
	drain(t, a, press(a, "l"))
	if a.mode != modeUsers || len(backend.Ran()) != 0 {
		t.Errorf("a key pressed while a command runs must be ignored")
	}
}

// TestLockingRefusesAnUnknownPasswordState covers the unprivileged machine:
// without /etc/shadow the tool does not know whether an account is locked, and
// a lock or an unlock would be a guess.
func TestLockingRefusesAnUnknownPasswordState(t *testing.T) {
	a, backend := newTestApp(t)
	selectUser(t, a, "alice")
	for i := range a.visibleUsers {
		a.visibleUsers[i].Password = accounts.PasswordUnknown
	}

	drain(t, a, press(a, "l"))
	if a.mode == modeConfirm {
		t.Error("a lock was offered for an account whose state is unknown")
	}
	if !strings.Contains(a.status, "unknown") {
		t.Errorf("status = %q", a.status)
	}
	if len(backend.Ran()) != 0 {
		t.Error("a command ran")
	}
}

// TestCreateFormBuildsUseradd walks the guided form the way a user does.
func TestCreateFormBuildsUseradd(t *testing.T) {
	a, backend := newTestApp(t)
	drain(t, a, press(a, "n"))
	if a.mode != modeForm {
		t.Fatalf("n did not open the create form (status: %s)", a.status)
	}
	a.form.fields[0].input.SetValue("dana")
	drain(t, a, press(a, "enter"))

	if a.mode != modeConfirm {
		t.Fatalf("the form did not open a confirm dialog (status: %s)", a.status)
	}
	want := "sudo -n useradd -m dana"
	if a.confirm.Command != want {
		t.Errorf("previewed %q, want %q", a.confirm.Command, want)
	}
	if !strings.Contains(a.confirm.Body, "no usable password") {
		t.Errorf("the dialog does not say the account cannot be logged into: %q",
			a.confirm.Body)
	}

	drain(t, a, press(a, "y"))
	if got := backend.Preview(backend.Ran()[0]); got != want {
		t.Errorf("ran %q", got)
	}
	// The demo machine applies it, so the account is really there afterwards.
	if _, ok := a.model.User("dana"); !ok {
		t.Error("the sample machine did not gain the account")
	}
}

// TestExpiryFormBuildsTwoChageCalls covers the form whose two answers are
// independent: each one is its own command, and both are previewed.
func TestExpiryFormBuildsTwoChageCalls(t *testing.T) {
	a, backend := newTestApp(t)
	selectUser(t, a, "alice")
	drain(t, a, press(a, "e"))
	if a.mode != modeForm {
		t.Fatalf("e did not open the expiry form (status: %s)", a.status)
	}
	a.form.fields[0].input.SetValue("2027-01-31")
	a.form.fields[1].input.SetValue("90")
	drain(t, a, press(a, "enter"))

	lines := strings.Split(a.confirm.Command, "\n")
	if len(lines) != 2 {
		t.Fatalf("previewed %q", a.confirm.Command)
	}
	if !strings.Contains(lines[0], "chage -E 2027-01-31 alice") ||
		!strings.Contains(lines[1], "chage -M 90 alice") {
		t.Errorf("previewed %q", a.confirm.Command)
	}
	drain(t, a, press(a, "y"))
	if len(backend.Ran()) != 2 {
		t.Errorf("ran %v", backend.Ran())
	}
}

// TestKeyActionNeedsTheDetailRead: the keys of an account are read when it is
// opened, so the action says so rather than showing an empty list.
func TestKeyActionNeedsTheDetailRead(t *testing.T) {
	a, _ := newTestApp(t)
	selectUser(t, a, "alice")
	drain(t, a, press(a, "K"))
	if a.mode == modePicker {
		t.Error("the keys picker opened before the account was read")
	}
	if !strings.Contains(a.status, "open the account first") {
		t.Errorf("status = %q", a.status)
	}
}

// openGroups moves to the groups screen and puts the cursor on one group.
func openGroups(t *testing.T, a *app, name string) {
	t.Helper()
	a.mode, a.previous = modeGroups, modeGroups
	for i, group := range a.visibleGroups {
		if group.Name == name {
			a.groups.cursor = i
			return
		}
	}
	t.Fatalf("no group named %q on the sample machine", name)
}

// TestGroupFormBuildsGroupadd walks the new-group form the way a user does,
// and checks the sample machine really gained the group.
func TestGroupFormBuildsGroupadd(t *testing.T) {
	a, backend := newTestApp(t)
	drain(t, a, press(a, "tab"))
	if a.mode != modeGroups {
		t.Fatalf("tab did not open the groups screen")
	}
	drain(t, a, press(a, "n"))
	if a.mode != modeForm {
		t.Fatalf("n did not open the group form (status: %s)", a.status)
	}
	a.form.fields[0].input.SetValue("developers")
	a.form.fields[1].input.SetValue("1500")
	drain(t, a, press(a, "enter"))

	if a.mode != modeConfirm {
		t.Fatalf("the form did not open a confirm dialog (status: %s)", a.status)
	}
	want := "sudo -n groupadd -g 1500 developers"
	if a.confirm.Command != want {
		t.Errorf("previewed %q, want %q", a.confirm.Command, want)
	}

	drain(t, a, press(a, "y"))
	if got := backend.Preview(backend.Ran()[0]); got != want {
		t.Errorf("ran %q, want the previewed %q", got, want)
	}
	group, ok := a.model.Group("developers")
	if !ok {
		t.Fatal("the sample machine did not gain the group")
	}
	if group.GID != 1500 {
		t.Errorf("gid = %d, want the one that was asked for", group.GID)
	}
}

// TestGroupFormRefusesAName covers the validation that stands between a typo
// and an argv run as root: the refusal reaches the status line, not groupadd.
func TestGroupFormRefusesAName(t *testing.T) {
	a, backend := newTestApp(t)
	drain(t, a, press(a, "tab"))
	drain(t, a, press(a, "n"))
	a.form.fields[0].input.SetValue("Dev Team")
	drain(t, a, press(a, "enter"))

	if a.mode == modeConfirm {
		t.Error("a confirm dialog opened for a name groupadd would not take")
	}
	if !strings.Contains(a.status, "not a valid group name") {
		t.Errorf("status = %q", a.status)
	}
	if len(backend.Ran()) != 0 {
		t.Error("a command ran")
	}
}

// TestDeletingAGroupNeedsItEmpty: every human group on the sample machine is
// somebody's primary group, which is the case people expect to work and
// groupdel refuses.
func TestDeletingAGroupNeedsItEmpty(t *testing.T) {
	a, backend := newTestApp(t)
	openGroups(t, a, "wheel")
	drain(t, a, press(a, "D"))

	if a.mode == modeConfirm || a.mode == modeInput {
		t.Fatal("a dialog opened for a group that still has members")
	}
	if !strings.Contains(a.status, "member") {
		t.Errorf("status = %q, want the reason", a.status)
	}
	if len(backend.Ran()) != 0 {
		t.Error("a command ran against a group with members")
	}
}

// TestDeletingASystemGroupAsksForItsName is the extra answer a package's group
// costs: the name, typed back, before the confirm dialog is even offered.
func TestDeletingASystemGroupAsksForItsName(t *testing.T) {
	a, backend := newTestApp(t)
	// Every system group of the sample machine has a member, so the test makes
	// an empty one: gid 500 is below the machine's human range.
	drain(t, a, press(a, "tab"))
	drain(t, a, press(a, "n"))
	a.form.fields[0].input.SetValue("legacy")
	a.form.fields[1].input.SetValue("500")
	drain(t, a, press(a, "enter"))
	drain(t, a, press(a, "y"))
	if group, ok := a.model.Group("legacy"); !ok || !group.System {
		t.Fatalf("the sample machine did not gain an empty system group: %+v",
			group)
	}
	// Everything from here is judged against the groupadd already recorded.
	ranBefore := len(backend.Ran())

	openGroups(t, a, "legacy")
	drain(t, a, press(a, "D"))
	if a.mode != modeInput {
		t.Fatalf("D did not ask for the name (status: %s)", a.status)
	}

	// The wrong name deletes nothing.
	a.input.Model.SetValue("wheel")
	drain(t, a, press(a, "enter"))
	if a.mode == modeConfirm {
		t.Fatal("a confirm dialog opened for a name that did not match")
	}
	if len(backend.Ran()) != ranBefore {
		t.Fatal("a command ran after a mistyped confirmation")
	}

	drain(t, a, press(a, "D"))
	a.input.Model.SetValue("legacy")
	drain(t, a, press(a, "enter"))
	if a.mode != modeConfirm {
		t.Fatalf("the typed name did not open the dialog (status: %s)", a.status)
	}
	want := "sudo -n groupdel legacy"
	if a.confirm.Command != want {
		t.Errorf("previewed %q, want %q", a.confirm.Command, want)
	}
	if !a.confirm.Danger {
		t.Error("deleting a group is a danger dialog")
	}
	if !strings.Contains(a.confirm.Body, "system group") {
		t.Errorf("the dialog does not say what kind of group this is: %q",
			a.confirm.Body)
	}

	drain(t, a, press(a, "y"))
	if got := backend.Preview(backend.Ran()[ranBefore]); got != want {
		t.Errorf("ran %q, want the previewed %q", got, want)
	}
	if _, ok := a.model.Group("legacy"); ok {
		t.Error("the sample machine still has the group")
	}
}

// TestSudoUsesTheMachinesOwnGroup covers both directions of the sudo key, and
// the fact the dialog has to carry: which group grants it here.
func TestSudoUsesTheMachinesOwnGroup(t *testing.T) {
	a, backend := newTestApp(t)
	// bob holds no sudo on the sample machine, so S grants it.
	selectUser(t, a, "bob")
	drain(t, a, press(a, "S"))
	if a.mode != modeConfirm {
		t.Fatalf("S did not open a confirm dialog (status: %s)", a.status)
	}
	want := "sudo -n gpasswd -a bob wheel"
	if a.confirm.Command != want {
		t.Errorf("previewed %q, want %q", a.confirm.Command, want)
	}
	if !strings.Contains(a.confirm.Body, "wheel") {
		t.Errorf("the dialog does not name the group: %q", a.confirm.Body)
	}
	drain(t, a, press(a, "y"))
	if got := backend.Preview(backend.Ran()[0]); got != want {
		t.Errorf("ran %q, want the previewed %q", got, want)
	}

	// alice holds it, so the same key takes it away.
	a, backend = newTestApp(t)
	selectUser(t, a, "alice")
	drain(t, a, press(a, "S"))
	want = "sudo -n gpasswd -d alice wheel"
	if a.confirm.Command != want {
		t.Fatalf("previewed %q, want %q", a.confirm.Command, want)
	}
	drain(t, a, press(a, "y"))
	if got := backend.Preview(backend.Ran()[0]); got != want {
		t.Errorf("ran %q, want the previewed %q", got, want)
	}
	if user, _ := a.model.User("alice"); user.Sudo.Granted() {
		t.Error("alice still holds sudo on the sample machine")
	}
}

// TestSudoRefusesTheLastAdministrator is the refusal that matters most: the
// command would work, and it would leave nobody able to run it again.
func TestSudoRefusesTheLastAdministrator(t *testing.T) {
	a, backend := newTestApp(t)
	// carol is the second member of wheel; take her out first.
	selectUser(t, a, "carol")
	drain(t, a, press(a, "S"))
	drain(t, a, press(a, "y"))
	if len(backend.Ran()) != 1 {
		t.Fatalf("ran %v", backend.Ran())
	}

	selectUser(t, a, "alice")
	drain(t, a, press(a, "S"))
	if a.mode == modeConfirm {
		t.Fatal("a dialog opened for the last account holding sudo")
	}
	if !strings.Contains(a.status, "only member") {
		t.Errorf("status = %q, want the reason", a.status)
	}
	if len(backend.Ran()) != 1 {
		t.Error("a command ran against the last administrator")
	}
}

// TestSudoRefusesAMachineWithNoSudoGroup: without wheel, sudo or admin there is
// nothing to add somebody to, and guessing one would be inventing a privilege
// path this tool does not own.
func TestSudoRefusesAMachineWithNoSudoGroup(t *testing.T) {
	a, backend := newTestApp(t)
	var kept []accounts.Group
	for _, group := range a.model.Groups {
		if group.Name != "wheel" {
			kept = append(kept, group)
		}
	}
	a.model.Groups = kept
	a.applyFilter()

	selectUser(t, a, "bob")
	drain(t, a, press(a, "S"))
	if a.mode == modeConfirm {
		t.Fatal("a dialog opened on a machine with no sudo group")
	}
	if !strings.Contains(a.status, "no sudo-granting group") {
		t.Errorf("status = %q", a.status)
	}
	if len(backend.Ran()) != 0 {
		t.Error("a command ran")
	}
}

func TestHelpListsEveryActionKey(t *testing.T) {
	// The help screen and the hint bar are built from the same table, and a
	// key that is not in it is a key nobody will find.
	keys := map[string]bool{}
	for _, hint := range helpKeys() {
		for _, key := range strings.Split(hint.Key, " / ") {
			keys[strings.TrimSpace(key)] = true
		}
	}
	for _, want := range []string{"n", "D", "l", "p", "a", "s", "e", "K", "S",
		"q"} {
		if !keys[want] {
			t.Errorf("the help screen does not mention %q", want)
		}
	}
}
