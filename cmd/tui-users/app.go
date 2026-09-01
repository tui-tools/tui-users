package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-users/internal/accounts"
	"github.com/tui-tools/tui-users/internal/shadow"
)

// mode is the screen the app currently shows. Only one dialog is open at a
// time, which keeps the update loop flat.
type mode int

const (
	modeUsers mode = iota
	modeUserDetail
	modeGroups
	modeGroupDetail
	modeSudoers
	modeConfirm
	modeFilter
	modeInput
	modePicker
	modeForm
	modeHelp
)

// isList reports whether a mode is one of the three list screens, which are
// what the tab key cycles through.
func (m mode) isList() bool {
	return m == modeUsers || m == modeGroups || m == modeSudoers
}

// inputTarget says what a text prompt's answer applies to.
type inputTarget int

const (
	inputNone inputTarget = iota
	inputPassword
	inputKey
	// inputGroupName is the typed confirmation a system group's deletion asks
	// for: the name, back, before the dialog is even offered.
	inputGroupName
)

// pickerTarget says what an open picker is choosing.
type pickerTarget int

const (
	pickerNone pickerTarget = iota
	pickerShell
	pickerAddGroup
	pickerRemoveGroup
	pickerKeys
	pickerDelete
	pickerFormChoice
)

// listState is the cursor and viewport of one list screen. Each screen keeps
// its own, so switching to the groups and back does not lose the account you
// were looking at.
type listState struct {
	cursor int
	offset int
}

// app is the tui-users Bubble Tea model.
type app struct {
	backend accounts.Backend
	theme   theme.Theme
	caps    accounts.Capabilities
	// backendCompat is what the version probe found, rendered in the header.
	backendCompat compat.Result

	model accounts.Model
	// visible holds what is left after the filter, in display order.
	visibleUsers  []accounts.User
	visibleGroups []accounts.Group
	visibleRules  []accounts.SudoersEntry

	width, height int
	users         listState
	groups        listState
	rules         listState
	filter        string

	// detail holds the account the detail screen is showing, re-read in full,
	// and group the group whose members are on screen.
	detail       accounts.User
	detailOffset int
	group        accounts.Group

	mode mode
	// previous is the list screen a dialog or a detail screen returns to.
	previous mode

	confirm ui.Confirm
	input   ui.Input
	picker  ui.Picker
	form    userForm

	inputFor  inputTarget
	pickerFor pickerTarget

	status     string
	statusKind ui.StatusKind
	loading    bool
	// loadFailed reports that the last Load returned an error, so the empty
	// state does not claim the machine simply has no accounts.
	loadFailed bool
	// busy blocks input while a command runs.
	busy bool
}

// loadedMsg carries the result of a Load.
type loadedMsg struct {
	model accounts.Model
	err   error
}

// detailMsg carries the result of a per-account read.
type detailMsg struct {
	user accounts.User
	err  error
}

// ranMsg carries the result of running a plan.
type ranMsg struct {
	// title is the plan's title, echoed in the status line.
	title  string
	output string
	err    error
}

// plan is what a confirm dialog is holding: one or more commands, run in
// order. Most actions are a single command; adding an authorized key is three,
// and all of them are shown before any of them runs.
type plan struct {
	title    string
	commands []accounts.Command
}

// newApp builds the model around a backend.
func newApp(backend accounts.Backend, th theme.Theme,
	backendCompat compat.Result) *app {
	a := &app{
		backend:       backend,
		theme:         th,
		caps:          backend.Capabilities(),
		backendCompat: backendCompat,
		width:         80,
		height:        24,
		loading:       true,
		mode:          modeUsers,
		previous:      modeUsers,
	}
	if th.Warning != "" {
		a.setStatus(ui.StatusWarn, th.Warning)
	}
	return a
}

// Init starts the first load.
func (a *app) Init() tea.Cmd { return a.load() }

// load reads the accounts in the background.
func (a *app) load() tea.Cmd {
	backend := a.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		model, err := backend.Load(ctx)
		return loadedMsg{model: model, err: err}
	}
}

// loadDetail re-reads one account in full in the background.
func (a *app) loadDetail(user accounts.User) tea.Cmd {
	backend := a.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		detailed, err := backend.LoadUser(ctx, user)
		return detailMsg{user: detailed, err: err}
	}
}

// run executes a confirmed plan in the background, one command at a time,
// stopping at the first failure.
func (a *app) run(p plan) tea.Cmd {
	backend := a.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		var outputs []string
		for _, cmd := range p.commands {
			out, err := backend.Run(ctx, cmd)
			if err != nil {
				return ranMsg{title: p.title, output: out, err: err}
			}
			if trimmed := strings.TrimSpace(out); trimmed != "" {
				outputs = append(outputs, trimmed)
			}
		}
		return ranMsg{title: p.title, output: strings.Join(outputs, "; ")}
	}
}

// setStatus records a plain message for the status line.
func (a *app) setStatus(kind ui.StatusKind, message string) {
	a.status = message
	a.statusKind = kind
}

// setStatusf records a formatted message for the status line.
func (a *app) setStatusf(kind ui.StatusKind, format string, args ...any) {
	a.setStatus(kind, fmt.Sprintf(format, args...))
}

// Update is the main event loop.
func (a *app) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = msg.Width, msg.Height
		a.clampCursor()
		return a, nil

	case loadedMsg:
		a.loading = false
		if msg.err != nil {
			a.loadFailed = true
			a.setStatus(ui.StatusError, msg.err.Error())
			return a, nil
		}
		a.loadFailed = false
		a.model = msg.model
		a.applyFilter()
		// A detail screen that is open is showing an account the change may
		// have altered, so it is re-read too.
		if a.detail.Name != "" {
			if current, ok := a.model.User(a.detail.Name); ok {
				return a, a.loadDetail(current)
			}
			// The account is gone — deleted, most likely by the command that
			// triggered this reload.
			a.detail = accounts.User{}
			if a.mode == modeUserDetail {
				a.mode = modeUsers
			}
		}
		return a, nil

	case detailMsg:
		if msg.err != nil {
			a.setStatus(ui.StatusError, msg.err.Error())
			return a, nil
		}
		a.detail = msg.user
		return a, nil

	case ranMsg:
		a.busy = false
		if msg.err != nil {
			a.setStatus(ui.StatusError, msg.err.Error())
			return a, a.load()
		}
		summary := strings.TrimSpace(msg.output)
		if summary == "" {
			summary = "done"
		}
		a.setStatusf(ui.StatusOK, "%s: %s", msg.title, firstLine(summary))
		a.loading = true
		return a, a.load()

	case tea.KeyMsg:
		return a.handleKey(msg)
	}

	// Anything else (cursor blink, …) only concerns an open text input.
	if a.mode == modeFilter || a.mode == modeInput {
		cmd, _ := a.input.Update(msg)
		return a, cmd
	}
	if a.mode == modeForm {
		return a, a.form.updateActive(msg)
	}
	return a, nil
}

// handleKey routes a key press to the open dialog, or to the current screen.
func (a *app) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// ctrl+c always quits, even mid-dialog.
	if msg.Type == tea.KeyCtrlC {
		return a, tea.Quit
	}
	if a.busy {
		// A command is running: swallow input rather than queueing surprises.
		return a, nil
	}

	switch a.mode {
	case modeConfirm:
		return a.handleConfirm(msg)
	case modeFilter:
		return a.handleFilter(msg)
	case modeInput:
		return a.handleInput(msg)
	case modePicker:
		return a.handlePicker(msg)
	case modeForm:
		return a.handleForm(msg)
	case modeHelp:
		a.mode = a.previous
		return a, nil
	case modeUserDetail:
		return a.handleDetailKey(msg)
	case modeGroupDetail:
		return a.handleGroupDetailKey(msg)
	case modeGroups:
		return a.handleGroupsKey(msg)
	case modeSudoers:
		return a.handleSudoersKey(msg)
	default:
		return a.handleUsersKey(msg)
	}
}

// handleConfirm resolves the confirm dialog.
func (a *app) handleConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	a.confirm.Update(msg)
	if !a.confirm.Done {
		return a, nil
	}
	a.mode = a.previous
	confirmed := a.confirm.Confirmed
	pending, ok := a.confirm.Payload.(plan)
	a.confirm = ui.Confirm{}
	if !confirmed || !ok {
		a.setStatus(ui.StatusInfo, "cancelled")
		return a, nil
	}
	a.busy = true
	a.setStatusf(ui.StatusInfo, "running %s…", a.backend.Preview(pending.commands[0]))
	return a, a.run(pending)
}

// handleFilter resolves the filter prompt.
func (a *app) handleFilter(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	cmd, _ := a.input.Update(msg)
	if !a.input.Done {
		// Filter as the user types.
		a.filter = a.input.Value()
		a.applyFilter()
		return a, cmd
	}
	if a.input.Accepted {
		a.filter = a.input.Value()
	} else {
		a.filter = ""
	}
	a.applyFilter()
	a.mode = a.previous
	return a, nil
}

// handleInput resolves the password and authorized key prompts.
func (a *app) handleInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	cmd, _ := a.input.Update(msg)
	if !a.input.Done {
		return a, cmd
	}
	value := a.input.Value()
	accepted := a.input.Accepted
	target := a.inputFor
	name, _ := a.input.Payload.(string)
	a.input, a.inputFor = ui.Input{}, inputNone
	a.mode = a.previous

	if !accepted {
		a.setStatus(ui.StatusInfo, "cancelled")
		return a, nil
	}
	switch target {
	case inputPassword:
		return a, a.confirmPassword(name, value)
	case inputKey:
		return a, a.confirmAddKey(name, value)
	case inputGroupName:
		return a, a.confirmDeleteSystemGroup(name, value)
	default:
		return a, nil
	}
}

// handlePicker resolves the open picker.
func (a *app) handlePicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	a.picker.Update(msg)
	if !a.picker.Done {
		return a, nil
	}
	choice, accepted := a.picker.Selected(), a.picker.Accepted
	target := a.pickerFor
	name, _ := a.picker.Payload.(string)
	a.picker, a.pickerFor = ui.Picker{}, pickerNone

	if target == pickerFormChoice {
		a.mode = modeForm
		if accepted {
			a.form.setActiveValue(choice)
		}
		return a, nil
	}

	a.mode = a.previous
	if !accepted {
		a.setStatus(ui.StatusInfo, "cancelled")
		return a, nil
	}
	switch target {
	case pickerShell:
		return a, a.buildAndConfirm("Change the login shell",
			func() (accounts.Command, error) {
				return a.backend.BuildSetShell(name, choice)
			})
	case pickerAddGroup:
		return a, a.buildAndConfirm("Add to a group",
			func() (accounts.Command, error) {
				return a.backend.BuildGroupMembership(true, name, choice)
			})
	case pickerRemoveGroup:
		return a, a.buildAndConfirm("Remove from a group",
			func() (accounts.Command, error) {
				return a.backend.BuildGroupMembership(false, name, choice)
			})
	case pickerKeys:
		if choice == addKeyOption {
			return a, a.promptKey()
		}
		return a, a.confirmRemoveKey(strings.TrimPrefix(choice, removeKeyPrefix))
	case pickerDelete:
		return a, a.confirmDelete(name, choice == deleteWithHome)
	default:
		return a, nil
	}
}

// handleForm routes keys to the open form.
func (a *app) handleForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		a.mode = a.previous
		a.setStatus(ui.StatusInfo, "cancelled")
		return a, nil
	case "tab", "down":
		a.form.next()
		return a, nil
	case "shift+tab", "up":
		a.form.prev()
		return a, nil
	case "left":
		if a.form.activeIsChoice() {
			a.form.cycle(-1)
			return a, nil
		}
	case "right":
		if a.form.activeIsChoice() {
			a.form.cycle(1)
			return a, nil
		}
	case "enter":
		if a.form.activeIsChoice() {
			// A choice field opens a picker: better than cycling a long list.
			a.picker = ui.NewPicker(a.form.activeLabel(),
				a.form.activeOptions(), a.form.activeValue())
			a.pickerFor = pickerFormChoice
			a.mode = modePicker
			return a, nil
		}
		return a, a.submitForm()
	}
	return a, a.form.updateActive(msg)
}

// submitForm turns the open form into a confirm dialog.
func (a *app) submitForm() tea.Cmd {
	switch a.form.kind {
	case formCreate:
		commands, err := a.backend.BuildCreateUser(a.form.newUser())
		if err != nil {
			a.setStatus(ui.StatusError, err.Error())
			return nil
		}
		a.mode = modeConfirm
		a.confirm = ui.Confirm{
			Title: "Create " + a.form.newUser().Name,
			Body: commands[0].Description + ".\nThe account is created with no " +
				"usable password: set one, or add an authorized key, before it " +
				"can be logged into.",
			Command: a.previewAll(commands),
			Payload: plan{title: "Create the account", commands: commands},
		}
		return nil
	case formExpiry:
		expires, maxDays := a.form.expiry()
		commands, err := a.backend.BuildSetExpiry(a.form.subject, expires, maxDays)
		if err != nil {
			a.setStatus(ui.StatusError, err.Error())
			return nil
		}
		a.mode = modeConfirm
		a.confirm = ui.Confirm{
			Title:   "Expiry for " + a.form.subject,
			Body:    describeAll(commands),
			Command: a.previewAll(commands),
			Danger:  true,
			Payload: plan{title: "Set the expiry", commands: commands},
		}
		return nil
	case formGroup:
		spec := a.form.newGroup()
		cmd, err := a.backend.BuildCreateGroup(spec)
		if err != nil {
			a.setStatus(ui.StatusError, err.Error())
			return nil
		}
		a.mode = modeConfirm
		a.confirm = ui.Confirm{
			Title: "Create the group " + spec.Name,
			Body: cmd.Description + ".\nIt starts empty: accounts join it from " +
				"their own screen, with a.",
			Command: a.backend.Preview(cmd),
			Payload: plan{title: "Create the group",
				commands: []accounts.Command{cmd}},
		}
		return nil
	}
	return nil
}

// previewAll renders every command of a plan, one per line, each with the
// prompt the dialog puts in front of the first one.
func (a *app) previewAll(commands []accounts.Command) string {
	previews := make([]string, 0, len(commands))
	for _, cmd := range commands {
		previews = append(previews, a.backend.Preview(cmd))
	}
	return strings.Join(previews, "\n$ ")
}

// describeAll renders the descriptions of a multi-command plan as a list.
func describeAll(commands []accounts.Command) string {
	lines := make([]string, 0, len(commands))
	for _, cmd := range commands {
		lines = append(lines, "· "+cmd.Description)
	}
	return strings.Join(lines, "\n")
}

// handleUsersKey handles the accounts screen.
func (a *app) handleUsersKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		return a, tea.Quit
	case "?":
		a.previous, a.mode = modeUsers, modeHelp
	case "tab":
		a.switchTo(modeGroups)
	case "shift+tab":
		a.switchTo(modeSudoers)
	case "j", "down":
		a.moveCursor(1)
	case "k", "up":
		a.moveCursor(-1)
	case "g", "home":
		a.users = listState{}
	case "G", "end":
		a.users.cursor = max(len(a.visibleUsers)-1, 0)
		a.clampCursor()
	case "pgdown", "ctrl+f":
		a.moveCursor(a.tableHeight())
	case "pgup", "ctrl+b":
		a.moveCursor(-a.tableHeight())
	case "/":
		a.openFilter("accounts", "name, uid, shell, group…")
	case "enter":
		return a, a.openDetail()
	case "R", "ctrl+r":
		a.loading = true
		return a, a.load()
	default:
		return a, a.handleActionKey(msg)
	}
	return a, nil
}

// handleDetailKey handles the per-account screen. The action keys are the same
// ones the list offers, applied to the account on screen.
func (a *app) handleDetailKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "backspace", "left":
		a.detail, a.detailOffset = accounts.User{}, 0
		a.mode = modeUsers
		return a, nil
	case "?":
		a.previous, a.mode = modeUserDetail, modeHelp
		return a, nil
	case "j", "down":
		a.detailOffset++
		return a, nil
	case "k", "up":
		a.detailOffset = max(a.detailOffset-1, 0)
		return a, nil
	case "g", "home":
		a.detailOffset = 0
		return a, nil
	case "pgdown", "ctrl+f":
		a.detailOffset += a.detailHeight()
		return a, nil
	case "pgup", "ctrl+b":
		a.detailOffset = max(a.detailOffset-a.detailHeight(), 0)
		return a, nil
	case "R", "ctrl+r":
		return a, a.loadDetail(a.detail)
	default:
		return a, a.handleActionKey(msg)
	}
}

// handleGroupsKey handles the groups screen.
func (a *app) handleGroupsKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		return a, tea.Quit
	case "?":
		a.previous, a.mode = modeGroups, modeHelp
	case "tab":
		a.switchTo(modeSudoers)
	case "shift+tab":
		a.switchTo(modeUsers)
	case "j", "down":
		a.moveCursor(1)
	case "k", "up":
		a.moveCursor(-1)
	case "g", "home":
		a.groups = listState{}
	case "G", "end":
		a.groups.cursor = max(len(a.visibleGroups)-1, 0)
		a.clampCursor()
	case "pgdown", "ctrl+f":
		a.moveCursor(a.tableHeight())
	case "pgup", "ctrl+b":
		a.moveCursor(-a.tableHeight())
	case "/":
		a.openFilter("groups", "name, gid, member…")
	case "enter":
		if group, ok := a.currentGroup(); ok {
			a.group = group
			a.previous, a.mode = modeGroups, modeGroupDetail
			a.detailOffset = 0
		}
	case "R", "ctrl+r":
		a.loading = true
		return a, a.load()
	default:
		return a, a.handleGroupActionKey(msg)
	}
	return a, nil
}

// handleGroupDetailKey handles the members screen of one group.
func (a *app) handleGroupDetailKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "backspace", "left":
		a.mode, a.detailOffset = modeGroups, 0
		return a, nil
	case "?":
		a.previous, a.mode = modeGroupDetail, modeHelp
	case "j", "down":
		a.detailOffset++
	case "k", "up":
		a.detailOffset = max(a.detailOffset-1, 0)
	case "R", "ctrl+r":
		a.loading = true
		return a, a.load()
	default:
		return a, a.handleGroupActionKey(msg)
	}
	return a, nil
}

// handleGroupActionKey handles the keys that mean the same thing on the groups
// list and on one group's members screen.
func (a *app) handleGroupActionKey(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "n":
		return a.openGroupForm()
	case "D":
		return a.promptDeleteGroup()
	}
	return nil
}

// handleSudoersKey handles the sudoers screen, which is read-only in v0.1.
func (a *app) handleSudoersKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		return a, tea.Quit
	case "?":
		a.previous, a.mode = modeSudoers, modeHelp
	case "tab":
		a.switchTo(modeUsers)
	case "shift+tab":
		a.switchTo(modeGroups)
	case "j", "down":
		a.moveCursor(1)
	case "k", "up":
		a.moveCursor(-1)
	case "g", "home":
		a.rules = listState{}
	case "G", "end":
		a.rules.cursor = max(len(a.visibleRules)-1, 0)
		a.clampCursor()
	case "pgdown", "ctrl+f":
		a.moveCursor(a.tableHeight())
	case "pgup", "ctrl+b":
		a.moveCursor(-a.tableHeight())
	case "/":
		a.openFilter("sudo rules", "user, file, NOPASSWD…")
	case "R", "ctrl+r":
		a.loading = true
		return a, a.load()
	}
	return a, nil
}

// switchTo moves between the list screens, keeping each one's cursor.
func (a *app) switchTo(target mode) {
	a.mode, a.previous = target, target
	a.clampCursor()
}

// openFilter opens the filter prompt for the current screen.
func (a *app) openFilter(what, placeholder string) {
	a.input = ui.NewInput("Filter "+what, placeholder, a.filter)
	a.input.Help = "Matches any column. Empty clears the filter."
	a.previous = a.mode
	a.mode = modeFilter
}

// handleActionKey handles the keys that mean the same thing on the accounts
// list and on the detail screen.
func (a *app) handleActionKey(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "n":
		return a.openCreateForm()
	case "D":
		return a.promptDelete()
	case "l":
		return a.confirmLock()
	case "p":
		return a.promptPassword()
	case "a":
		return a.promptGroup(true)
	case "x":
		return a.promptGroup(false)
	case "S":
		return a.confirmSudo()
	case "s":
		return a.promptShell()
	case "e":
		return a.openExpiryForm()
	case "K":
		return a.promptKeys()
	}
	return nil
}

// currentUser is the account the action keys apply to: the one the detail
// screen is showing, or the highlighted row of the list.
func (a *app) currentUser() (accounts.User, bool) {
	if a.mode == modeUserDetail && a.detail.Name != "" {
		return a.detail, true
	}
	if a.users.cursor < 0 || a.users.cursor >= len(a.visibleUsers) {
		return accounts.User{}, false
	}
	return a.visibleUsers[a.users.cursor], true
}

// requireUser returns the current account, or says there is none.
func (a *app) requireUser() (accounts.User, bool) {
	user, ok := a.currentUser()
	if !ok {
		a.setStatus(ui.StatusWarn, "no account selected")
		return accounts.User{}, false
	}
	return user, true
}

// currentGroup is the highlighted group.
func (a *app) currentGroup() (accounts.Group, bool) {
	if a.groups.cursor < 0 || a.groups.cursor >= len(a.visibleGroups) {
		return accounts.Group{}, false
	}
	return a.visibleGroups[a.groups.cursor], true
}

// groupTarget is the group the group actions apply to: the one the members
// screen is showing, or the highlighted row of the list. The model's copy wins,
// so a deletion is judged on the membership of the last read rather than on the
// one the screen was opened with.
func (a *app) groupTarget() (accounts.Group, bool) {
	group, ok := a.currentGroup()
	if a.mode == modeGroupDetail && a.group.Name != "" {
		group, ok = a.group, true
	}
	if !ok {
		return accounts.Group{}, false
	}
	if current, found := a.model.Group(group.Name); found {
		return current, true
	}
	return group, true
}

// requireGroup returns the current group, or says there is none.
func (a *app) requireGroup() (accounts.Group, bool) {
	group, ok := a.groupTarget()
	if !ok {
		a.setStatus(ui.StatusWarn, "no group selected")
		return accounts.Group{}, false
	}
	return group, true
}

// openDetail re-reads the highlighted account and opens its screen.
func (a *app) openDetail() tea.Cmd {
	user, ok := a.requireUser()
	if !ok {
		return nil
	}
	a.detail, a.detailOffset = user, 0
	a.previous, a.mode = modeUsers, modeUserDetail
	return a.loadDetail(user)
}

// openCreateForm opens the guided form for a new account.
func (a *app) openCreateForm() tea.Cmd {
	if !a.caps.SupportsCreate {
		a.setStatus(ui.StatusWarn, "useradd is not available on this machine")
		return nil
	}
	a.form = newCreateForm(a.caps)
	a.previous = a.mode
	a.mode = modeForm
	return nil
}

// openExpiryForm opens the guided form for an account's expiry policy.
func (a *app) openExpiryForm() tea.Cmd {
	if !a.caps.SupportsExpiry {
		a.setStatus(ui.StatusWarn, "chage is not available on this machine")
		return nil
	}
	user, ok := a.requireUser()
	if !ok {
		return nil
	}
	a.form = newExpiryForm(user)
	a.previous = a.mode
	a.mode = modeForm
	return nil
}

// openGroupForm opens the guided form for a new group.
func (a *app) openGroupForm() tea.Cmd {
	if !a.caps.SupportsGroupCreate {
		a.setStatus(ui.StatusWarn, "groupadd is not available on this machine")
		return nil
	}
	a.form = newGroupForm()
	a.previous = a.mode
	a.mode = modeForm
	return nil
}

// promptDeleteGroup deletes the selected group, or says why it will not.
//
// A group with members is refused outright, because emptying it would change
// what every one of those accounts can do. A system group is refused too,
// unless its name is typed back: the GID range the machine declares in
// /etc/login.defs is what tells a package's group from a person's.
func (a *app) promptDeleteGroup() tea.Cmd {
	if !a.caps.SupportsGroupDelete {
		a.setStatus(ui.StatusWarn, "groupdel is not available on this machine")
		return nil
	}
	group, ok := a.requireGroup()
	if !ok {
		return nil
	}
	if members := group.All(); len(members) > 0 {
		a.setStatusf(ui.StatusWarn,
			"%s still has %d member(s) — %s — so it cannot be deleted; "+
				"remove them from their own screens first",
			group.Name, len(members), strings.Join(members, ", "))
		return nil
	}
	if group.System {
		a.input = ui.NewInput("Delete the system group "+group.Name,
			group.Name, "")
		a.input.Help = fmt.Sprintf(
			"gid %d is outside the machine's human range, so a package owns "+
				"this group. Type %s to confirm; anything else cancels.",
			group.GID, group.Name)
		a.input.Payload = group.Name
		a.inputFor = inputGroupName
		a.previous = a.mode
		a.mode = modeInput
		return nil
	}
	return a.confirmDeleteGroup(group, false)
}

// confirmDeleteSystemGroup opens the dialog only when the typed name is the
// group's own.
func (a *app) confirmDeleteSystemGroup(name, typed string) tea.Cmd {
	if strings.TrimSpace(typed) != name {
		a.setStatusf(ui.StatusWarn,
			"that is not %s: the system group was left alone", name)
		return nil
	}
	group, ok := a.model.Group(name)
	if !ok {
		a.setStatusf(ui.StatusError, "no group named %s", name)
		return nil
	}
	return a.confirmDeleteGroup(group, true)
}

// confirmDeleteGroup opens the confirm dialog for a group deletion.
func (a *app) confirmDeleteGroup(group accounts.Group, allowSystem bool) tea.Cmd {
	cmd, err := a.backend.BuildDeleteGroup(group, allowSystem)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	body := fmt.Sprintf("%s (gid %d).\nIt has no members, so no account loses "+
		"anything. Files owned by that gid stay, owned by a group nobody has.",
		cmd.Description, group.GID)
	if allowSystem {
		body += "\nThis is a system group: whatever package created it expects " +
			"to find it there."
	}
	a.openConfirm("Delete the group "+group.Name, body, cmd)
	return nil
}

// confirmSudo grants or revokes sudo for the current account.
//
// It is the group membership action with the group filled in by the machine —
// wheel here, sudo there — because "give this person sudo" is the question, and
// which group answers it is the distribution's business rather than the
// operator's.
func (a *app) confirmSudo() tea.Cmd {
	if !a.caps.SupportsGroups {
		a.setStatus(ui.StatusWarn, "gpasswd is not available on this machine")
		return nil
	}
	user, ok := a.requireUser()
	if !ok {
		return nil
	}
	group, ok := a.model.SudoGroup(a.caps.SudoGroups)
	if !ok {
		a.setStatusf(ui.StatusWarn,
			"no sudo-granting group exists here (looked for %s): sudo must then "+
				"come from a rule in /etc/sudoers, which this tool does not edit",
			strings.Join(a.caps.SudoGroups, ", "))
		return nil
	}

	members := a.model.SudoMembers(group)
	grant := !holdsSudo(user, group)
	if !grant && len(members) <= 1 {
		a.setStatusf(ui.StatusWarn,
			"%s is the only member of %s — revoking it would leave the machine "+
				"with no administrator but root", user.Name, group)
		return nil
	}

	cmd, err := a.backend.BuildSudo(grant, user.Name, group)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	body := cmd.Description + "."
	if grant {
		body += fmt.Sprintf("\nOn this machine %s is what grants sudo: every "+
			"account in it can become root. Check the sudo rules screen for "+
			"what the group is actually given.", group)
	} else {
		body += fmt.Sprintf("\n%d other account(s) keep sudo through %s.\n"+
			"A rule naming %s directly in a sudoers file would survive this — "+
			"the sudo rules screen is where to look.",
			len(members)-1, group, user.Name)
	}
	a.openConfirm(cmd.Description, body, cmd)
	return nil
}

// holdsSudo reports whether an account already holds sudo through a group. It
// reads the memberships the backend's own sudo detection put on the account, so
// the answer is the one the list column and the detail screen show.
func holdsSudo(user accounts.User, group string) bool {
	for _, name := range user.Sudo.Groups {
		if name == group {
			return true
		}
	}
	return false
}

// deleteWithHome and deleteKeepHome are the two answers the delete picker
// offers. They are spelled out rather than offered as a yes/no, because
// "delete the home directory" is the half that cannot be undone.
const (
	deleteWithHome = "delete the account and remove its home directory"
	deleteKeepHome = "delete the account and keep its home directory"
)

// promptDelete asks which kind of deletion this is.
func (a *app) promptDelete() tea.Cmd {
	if !a.caps.SupportsDelete {
		a.setStatus(ui.StatusWarn, "userdel is not available on this machine")
		return nil
	}
	user, ok := a.requireUser()
	if !ok {
		return nil
	}
	if user.Name == "root" {
		a.setStatus(ui.StatusWarn, "root cannot be deleted")
		return nil
	}
	if sessions := a.model.SessionsFor(user.Name); len(sessions) > 0 {
		a.setStatusf(ui.StatusWarn,
			"%s is logged in right now (session %s) — userdel would refuse",
			user.Name, sessions[0].ID)
		return nil
	}
	a.openPicker("Delete "+user.Name,
		[]string{deleteKeepHome, deleteWithHome}, deleteKeepHome,
		pickerDelete, user.Name)
	return nil
}

// confirmDelete opens the confirm dialog for a deletion.
func (a *app) confirmDelete(name string, removeHome bool) tea.Cmd {
	cmd, err := a.backend.BuildDeleteUser(name, removeHome)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	body := cmd.Description + "."
	if removeHome {
		body += "\nEverything in the home directory goes with it. " +
			"Files the account owns elsewhere stay, owned by a UID nobody has."
	} else {
		body += "\nThe home directory stays, owned by a UID nobody has, " +
			"and a new account could be given that UID."
	}
	a.openConfirm("Delete "+name, body, cmd)
	return nil
}

// confirmLock locks or unlocks the current account.
func (a *app) confirmLock() tea.Cmd {
	if !a.caps.SupportsLock {
		a.setStatus(ui.StatusWarn, "usermod is not available on this machine")
		return nil
	}
	user, ok := a.requireUser()
	if !ok {
		return nil
	}
	if user.Password == accounts.PasswordUnknown {
		a.setStatus(ui.StatusWarn,
			"the password state is unknown here: /etc/shadow could not be read, "+
				"so locking or unlocking would be a guess")
		return nil
	}
	lock := user.Password != accounts.PasswordLocked
	cmd, err := a.backend.BuildLock(user.Name, lock)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	body := cmd.Description + "."
	if lock {
		body += "\n`usermod -L` puts a \"!\" in front of the stored hash, " +
			"exactly as `passwd -l` does: the password stops working and " +
			"unlocking brings it back.\nIt stops password logins only — " +
			"an authorized key still lets this account in over SSH."
		if len(user.Keys) > 0 {
			body += fmt.Sprintf("\nThis account has %d authorized key(s).",
				len(user.Keys))
		}
	} else {
		body += "\nThe password that was locked starts working again."
	}
	a.openConfirm(cmd.Description, body, cmd)
	return nil
}

// promptPassword opens the password prompt, which echoes nothing.
func (a *app) promptPassword() tea.Cmd {
	if !a.caps.SupportsPassword {
		a.setStatus(ui.StatusWarn, "chpasswd is not available on this machine")
		return nil
	}
	user, ok := a.requireUser()
	if !ok {
		return nil
	}
	a.input = ui.NewInput("New password for "+user.Name, "", "")
	a.input.Help = "Nothing is echoed. It goes to chpasswd on standard input, " +
		"never on a command line."
	a.input.Model.EchoMode = textinput.EchoPassword
	a.input.Model.EchoCharacter = '•'
	a.input.Payload = user.Name
	a.inputFor = inputPassword
	a.previous = a.mode
	a.mode = modeInput
	return nil
}

// confirmPassword opens the confirm dialog for a password change. The value
// itself appears nowhere: not in the preview, not in the body, not in the
// status line.
func (a *app) confirmPassword(name, password string) tea.Cmd {
	cmd, err := a.backend.BuildSetPassword(name, password)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	a.openConfirm("Set the password of "+name,
		"The password is written to chpasswd's standard input as\n"+
			name+":"+strings.Repeat("•", 8)+
			"\nso it never appears in the command line, and never in `ps`.",
		cmd)
	return nil
}

// promptGroup opens the group picker for adding or removing a membership.
func (a *app) promptGroup(add bool) tea.Cmd {
	if !a.caps.SupportsGroups {
		a.setStatus(ui.StatusWarn, "gpasswd is not available on this machine")
		return nil
	}
	user, ok := a.requireUser()
	if !ok {
		return nil
	}
	member := map[string]bool{user.PrimaryGroup: true}
	for _, group := range user.Groups {
		member[group] = true
	}

	var options []string
	for _, name := range a.model.GroupNames() {
		if member[name] == add {
			continue
		}
		options = append(options, name)
	}
	if len(options) == 0 {
		if add {
			a.setStatusf(ui.StatusInfo, "%s is already in every group", user.Name)
		} else {
			a.setStatusf(ui.StatusInfo,
				"%s has no supplementary group to leave", user.Name)
		}
		return nil
	}

	title := "Add " + user.Name + " to which group?"
	if !add {
		title = "Remove " + user.Name + " from which group?"
	}
	target := pickerAddGroup
	if !add {
		target = pickerRemoveGroup
	}
	a.openPicker(title, options, "", target, user.Name)
	return nil
}

// promptShell opens the shell picker, built from /etc/shells.
func (a *app) promptShell() tea.Cmd {
	if !a.caps.SupportsShell {
		a.setStatus(ui.StatusWarn, "usermod is not available on this machine")
		return nil
	}
	user, ok := a.requireUser()
	if !ok {
		return nil
	}
	shells := a.caps.Shells
	if len(shells) == 0 {
		a.setStatus(ui.StatusWarn, "/etc/shells lists no shell to choose from")
		return nil
	}
	a.openPicker("Login shell for "+user.Name, shells, user.Shell,
		pickerShell, user.Name)
	return nil
}

// promptKey opens the prompt that takes a pasted public key.
func (a *app) promptKey() tea.Cmd {
	if !a.caps.SupportsKeys {
		a.setStatus(ui.StatusWarn,
			"install and tee are needed to write an authorized_keys file")
		return nil
	}
	user, ok := a.requireUser()
	if !ok {
		return nil
	}
	if user.Home == "" {
		a.setStatusf(ui.StatusWarn, "%s has no home directory", user.Name)
		return nil
	}
	a.input = ui.NewInput("Authorized key for "+user.Name,
		"ssh-ed25519 AAAAC3… you@host", "")
	a.input.Help = "Paste the contents of a .pub file. " +
		"It is checked with ssh-keygen before anything is written."
	a.input.Payload = user.Name
	a.inputFor = inputKey
	a.previous = a.mode
	a.mode = modeInput
	return nil
}

// confirmAddKey validates a pasted key and opens the confirm dialog with the
// diff and the commands that apply it.
func (a *app) confirmAddKey(name, key string) tea.Cmd {
	user, ok := a.model.User(name)
	if !ok {
		a.setStatusf(ui.StatusError, "no account named %s", name)
		return nil
	}
	// The detail read is what knows the account's keys, and it is what the
	// diff is built against.
	if a.detail.Name == name {
		user = a.detail
	}
	plan, err := a.backend.BuildAddKey(user, key)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	body := a.diffForDialog(plan.Diff)
	// A FIDO key on an openssh too old to understand it would be written and
	// then ignored, which is the worst of both: the file says access was
	// granted and the machine disagrees. The version came from the manifest.
	if strings.HasPrefix(strings.TrimSpace(key), "sk-") &&
		!a.backendCompat.Caps().Has(shadow.FeatureSecurityKeys) {
		since, _ := a.backendCompat.Caps().Since(shadow.FeatureSecurityKeys)
		body += fmt.Sprintf("\n\nThis is a security-key type, which openssh "+
			"understands from %s; this machine runs %s, where sshd would "+
			"ignore the line.", since, a.backendCompat.Version)
	}
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title:   "Add an authorized key to " + name,
		Body:    body,
		Command: a.previewAll(plan.Commands),
		Danger:  true,
		Payload: planFor("Add an authorized key", plan),
	}
	return nil
}

// The two things the authorized-keys picker offers. They are one key rather
// than two because `k` is how a detail screen scrolls, and an action that
// stole it would cost more than it gave.
const (
	addKeyOption    = "add a key…"
	removeKeyPrefix = "remove: "
)

// promptKeys opens the picker over an account's authorized keys: add one, or
// remove one of the ones that are there.
func (a *app) promptKeys() tea.Cmd {
	if !a.caps.SupportsKeys {
		a.setStatus(ui.StatusWarn,
			"install and tee are needed to write an authorized_keys file")
		return nil
	}
	user, ok := a.requireUser()
	if !ok {
		return nil
	}
	if user.Home == "" {
		a.setStatusf(ui.StatusWarn, "%s has no home directory", user.Name)
		return nil
	}
	if !user.Detailed {
		a.setStatus(ui.StatusInfo,
			"open the account first: its keys are read on the detail screen")
		return nil
	}
	options := []string{addKeyOption}
	for _, key := range user.Keys {
		options = append(options, removeKeyPrefix+key.Label())
	}
	a.openPicker("Authorized keys of "+user.Name, options, addKeyOption,
		pickerKeys, user.Name)
	return nil
}

// confirmRemoveKey opens the confirm dialog for removing one key, with the
// diff of the file it rewrites.
func (a *app) confirmRemoveKey(label string) tea.Cmd {
	user := a.detail
	var chosen accounts.Key
	found := false
	for _, key := range user.Keys {
		if key.Label() == label {
			chosen, found = key, true
			break
		}
	}
	if !found {
		a.setStatus(ui.StatusError, "that key is no longer in the file")
		return nil
	}
	plan, err := a.backend.BuildRemoveKey(user, chosen)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title:   "Remove a key from " + user.Name,
		Body:    a.diffForDialog(plan.Diff),
		Command: a.previewAll(plan.Commands),
		Danger:  true,
		Payload: planFor("Remove an authorized key", plan),
	}
	return nil
}

// planFor turns a key plan into the confirm dialog's payload.
func planFor(title string, keys accounts.KeyPlan) plan {
	return plan{title: title, commands: keys.Commands}
}

// openPicker opens a picker and remembers what it is choosing.
func (a *app) openPicker(title string, options []string, current string,
	target pickerTarget, payload string) {
	a.picker = ui.NewPicker(title, options, current)
	a.picker.Payload = payload
	a.pickerFor = target
	a.previous = a.mode
	a.mode = modePicker
}

// buildAndConfirm runs a command builder and opens the confirm dialog, or
// reports the builder's error in the status line.
func (a *app) buildAndConfirm(title string,
	build func() (accounts.Command, error)) tea.Cmd {
	cmd, err := build()
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	a.openConfirm(title, cmd.Description+".", cmd)
	return nil
}

// openConfirm shows one command and what it does.
func (a *app) openConfirm(title, body string, cmd accounts.Command) {
	if a.mode.isList() || a.mode == modeUserDetail {
		a.previous = a.mode
	}
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title:   title,
		Body:    body,
		Command: a.backend.Preview(cmd),
		Danger:  cmd.Destructive,
		Payload: plan{title: title, commands: []accounts.Command{cmd}},
	}
}

// applyFilter recomputes the visible rows of every screen from the filter.
func (a *app) applyFilter() {
	needle := strings.ToLower(a.filter)

	a.visibleUsers = nil
	for _, user := range a.model.Users {
		if needle == "" || strings.Contains(strings.ToLower(userHaystack(user)), needle) {
			a.visibleUsers = append(a.visibleUsers, user)
		}
	}
	a.visibleGroups = nil
	for _, group := range a.model.Groups {
		if needle == "" || strings.Contains(strings.ToLower(groupHaystack(group)), needle) {
			a.visibleGroups = append(a.visibleGroups, group)
		}
	}
	a.visibleRules = nil
	for _, file := range a.model.Sudoers {
		for _, entry := range file.Entries {
			if needle == "" ||
				strings.Contains(strings.ToLower(entry.File+" "+entry.Text), needle) {
				a.visibleRules = append(a.visibleRules, entry)
			}
		}
	}
	a.clampCursor()
}

// userHaystack is the text the accounts filter matches against.
func userHaystack(u accounts.User) string {
	parts := []string{
		u.Name, accounts.UIDString(u.UID), u.GECOS, u.Home, u.Shell,
		u.PrimaryGroup, strings.Join(u.Groups, " "), u.Password, u.Reason(),
	}
	return strings.Join(parts, " ")
}

// groupHaystack is the text the groups filter matches against.
func groupHaystack(g accounts.Group) string {
	return g.Name + " " + accounts.UIDString(g.GID) + " " +
		strings.Join(g.All(), " ")
}

// list returns the cursor state of the screen on show.
func (a *app) list() *listState {
	switch a.mode {
	case modeGroups:
		return &a.groups
	case modeSudoers:
		return &a.rules
	default:
		return &a.users
	}
}

// moveCursor moves the selection and keeps the viewport in sync.
func (a *app) moveCursor(delta int) {
	a.list().cursor += delta
	a.clampCursor()
}

// clampCursor keeps every list's cursor and scroll offset within range.
func (a *app) clampCursor() {
	height := a.tableHeight()
	for _, pair := range []struct {
		state *listState
		count int
	}{
		{&a.users, len(a.visibleUsers)},
		{&a.groups, len(a.visibleGroups)},
		{&a.rules, len(a.visibleRules)},
	} {
		if pair.count == 0 {
			*pair.state = listState{}
			continue
		}
		pair.state.cursor = min(max(pair.state.cursor, 0), pair.count-1)
		if pair.state.cursor < pair.state.offset {
			pair.state.offset = pair.state.cursor
		}
		if pair.state.cursor >= pair.state.offset+height {
			pair.state.offset = pair.state.cursor - height + 1
		}
		pair.state.offset = max(min(pair.state.offset,
			max(pair.count-height, 0)), 0)
	}
}

// firstLine keeps status messages to one line.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
