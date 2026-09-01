package main

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-users/internal/accounts"
	"github.com/tui-tools/tui-users/internal/shadow"
)

// formKind says which form is open. They are the same widget with a different
// field list, because there is exactly one way to fill in a form in this tool.
type formKind int

const (
	formCreate formKind = iota
	formExpiry
	formGroup
)

// fieldKind tells a cycled choice from a free-text field.
type fieldKind int

const (
	fieldChoice fieldKind = iota
	fieldText
)

// The yes/no options of a choice field, spelled as words so the confirm dialog
// and the form agree on what "yes" meant.
const (
	answerYes = "yes"
	answerNo  = "no"
)

// formField is one row of a form.
type formField struct {
	// key identifies the field when the form is read back.
	key   string
	label string
	kind  fieldKind
	// options and choice hold the state of a choice field.
	options []string
	choice  int
	// input holds the state of a text field.
	input textinput.Model
	// help is a one-line hint shown under the form.
	help string
}

// value returns the current value of the field.
func (f formField) value() string {
	if f.kind == fieldChoice {
		if f.choice < 0 || f.choice >= len(f.options) {
			return ""
		}
		return f.options[f.choice]
	}
	return strings.TrimSpace(f.input.Value())
}

// userForm is the guided editor behind the create and expiry actions.
//
// It is guided rather than free: what it produces is a set of values the
// backend validates and turns into an argv, so the form cannot approve
// something the command builder would refuse.
type userForm struct {
	kind   formKind
	fields []formField
	active int
	// subject is the account the form applies to, empty when creating one.
	subject string
	// title is the dialog's heading.
	title string
}

// text builds a text field's input model.
func text(placeholder, value string) textinput.Model {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.SetValue(value)
	ti.CharLimit = 200
	ti.Prompt = ""
	return ti
}

// choice builds a choice field, selecting the current value.
func choice(key, label string, options []string, current, help string) formField {
	field := formField{key: key, label: label, kind: fieldChoice,
		options: options, help: help}
	for i, option := range options {
		if option == current {
			field.choice = i
		}
	}
	return field
}

// newCreateForm builds the form for a new account.
func newCreateForm(caps accounts.Capabilities) userForm {
	shells := caps.Shells
	if len(shells) == 0 {
		shells = []string{"/bin/bash", "/bin/sh"}
	}
	// "the useradd default" is offered first, because a machine's default
	// shell is a decision its distribution already made.
	shells = append([]string{defaultShell}, shells...)

	f := userForm{
		kind:  formCreate,
		title: "New account",
		fields: []formField{
			{key: "name", label: "Name", kind: fieldText,
				input: text("alice", ""),
				help:  "Lower case, starting with a letter or an underscore."},
			{key: "comment", label: "Full name", kind: fieldText,
				input: text("Alice Moreira", ""),
				help:  "The GECOS field. Optional."},
			choice("shell", "Shell", shells, defaultShell,
				"The login shell. /usr/sbin/nologin makes an account that "+
					"cannot start a session."),
			{key: "groups", label: "Groups", kind: fieldText,
				input: text("wheel docker", ""),
				help: "Supplementary groups, separated by spaces. " +
					"wheel or sudo is what grants sudo."},
			choice("home", "Create home", []string{answerYes, answerNo}, answerYes,
				"useradd -m. Without it the account has a home directory in "+
					"the passwd file and nothing on disk."),
			choice("system", "System account", []string{answerNo, answerYes}, answerNo,
				"useradd -r: a UID below the human range, and no aging. "+
					"For a service, not for a person."),
		},
	}
	f.focusActive()
	return f
}

// defaultShell is the choice that passes no -s at all, leaving useradd to use
// the machine's own default.
const defaultShell = "(the machine's default)"

// newExpiryForm builds the form for an account's expiry policy, seeded from
// what the account has now.
func newExpiryForm(user accounts.User) userForm {
	expires := user.Aging.Expires
	if expires == "" {
		expires = shadow.NeverExpires
	}
	maxDays := shadow.NeverExpires
	if user.Aging.Known && !user.Aging.NoExpiry() {
		maxDays = strconv.Itoa(user.Aging.MaxDays)
	}

	f := userForm{
		kind:    formExpiry,
		title:   "Expiry for " + user.Name,
		subject: user.Name,
		fields: []formField{
			{key: "expires", label: "Account expires", kind: fieldText,
				input: text("2027-01-31", expires),
				help: "chage -E: the day the account stops working. " +
					"A date as YYYY-MM-DD, or " + shadow.NeverExpires + "."},
			{key: "maxdays", label: "Password lifetime", kind: fieldText,
				input: text("90", maxDays),
				help: "chage -M: how many days a password may live. " +
					"A number of days, or " + shadow.NeverExpires + "."},
		},
	}
	f.focusActive()
	return f
}

// newGroupForm builds the form for a new group.
//
// The GID field is deliberately empty by default: a machine that picks its own
// GIDs out of /etc/login.defs never collides with itself, and a number typed
// here is one somebody has a reason for.
func newGroupForm() userForm {
	f := userForm{
		kind:  formGroup,
		title: "New group",
		fields: []formField{
			{key: "name", label: "Name", kind: fieldText,
				input: text("developers", ""),
				help:  "Lower case, starting with a letter or an underscore."},
			{key: "gid", label: "GID", kind: fieldText,
				input: text("(the next free one)", ""),
				help: "groupadd -g. Optional: empty lets groupadd take the " +
					"next free GID from the machine's own range."},
		},
	}
	f.focusActive()
	return f
}

// focusActive moves the text cursor to the active field.
func (f *userForm) focusActive() {
	for i := range f.fields {
		if f.fields[i].kind != fieldText {
			continue
		}
		if i == f.active {
			f.fields[i].input.Focus()
			continue
		}
		f.fields[i].input.Blur()
	}
}

// next moves to the following field.
func (f *userForm) next() {
	f.active = (f.active + 1) % len(f.fields)
	f.focusActive()
}

// prev moves to the previous field.
func (f *userForm) prev() {
	f.active = (f.active - 1 + len(f.fields)) % len(f.fields)
	f.focusActive()
}

// activeIsChoice reports whether the active field is a cycled choice.
func (f userForm) activeIsChoice() bool {
	return f.fields[f.active].kind == fieldChoice
}

// activeLabel, activeOptions and activeValue expose the active field to the
// picker dialog.
func (f userForm) activeLabel() string     { return f.fields[f.active].label }
func (f userForm) activeOptions() []string { return f.fields[f.active].options }
func (f userForm) activeValue() string     { return f.fields[f.active].value() }

// setActiveValue applies a value chosen in the picker.
func (f *userForm) setActiveValue(value string) {
	field := &f.fields[f.active]
	for i, option := range field.options {
		if option == value {
			field.choice = i
			return
		}
	}
}

// cycle moves a choice field one step.
func (f *userForm) cycle(delta int) {
	field := &f.fields[f.active]
	if len(field.options) == 0 {
		return
	}
	field.choice = (field.choice + delta + len(field.options)) % len(field.options)
}

// updateActive forwards a message to the active text field.
func (f *userForm) updateActive(msg tea.Msg) tea.Cmd {
	if f.fields[f.active].kind != fieldText {
		return nil
	}
	var cmd tea.Cmd
	f.fields[f.active].input, cmd = f.fields[f.active].input.Update(msg)
	return cmd
}

// get returns the value of a field by key.
func (f userForm) get(key string) string {
	for _, field := range f.fields {
		if field.key == key {
			return field.value()
		}
	}
	return ""
}

// newUser turns the create form into the spec the backend validates.
func (f userForm) newUser() accounts.NewUser {
	shell := f.get("shell")
	if shell == defaultShell {
		shell = ""
	}
	return accounts.NewUser{
		Name:       f.get("name"),
		Comment:    f.get("comment"),
		Shell:      shell,
		Groups:     strings.Fields(f.get("groups")),
		CreateHome: f.get("home") == answerYes,
		System:     f.get("system") == answerYes,
	}
}

// newGroup turns the group form into the spec the backend validates.
func (f userForm) newGroup() accounts.NewGroup {
	return accounts.NewGroup{Name: f.get("name"), GID: f.get("gid")}
}

// expiry turns the expiry form into the two values the backend takes.
func (f userForm) expiry() (expires, maxDays string) {
	return f.get("expires"), f.get("maxdays")
}

// view renders the form as a dialog.
func (f userForm) view(t theme.Theme, width, height int) string {
	labelWidth := 0
	for _, field := range f.fields {
		if w := len(field.label); w > labelWidth {
			labelWidth = w
		}
	}

	inner := min(max(width-8, 30), 72)
	valueWidth := max(inner-labelWidth-6, 10)

	lines := []string{t.Title.Render(f.title), ""}
	for i, field := range f.fields {
		label := t.Muted.Render(ui.Pad(field.label, labelWidth))
		var value string
		switch {
		case field.kind == fieldChoice:
			value = renderChoice(t, field, i == f.active, valueWidth)
		case i == f.active:
			field.input.Width = valueWidth - 2
			value = field.input.View()
		default:
			value = renderIdleText(t, field, valueWidth)
		}
		marker := "  "
		if i == f.active {
			marker = t.Accent.Render("> ")
		}
		lines = append(lines, marker+label+"  "+value)
	}

	if help := f.fields[f.active].help; help != "" {
		lines = append(lines, "", t.Muted.Render(ui.Truncate(help, inner-2)))
	}
	lines = append(lines, "",
		t.Key.Render("tab")+t.KeyDesc.Render(" next    ")+
			t.Key.Render("←/→")+t.KeyDesc.Render(" change    ")+
			t.Key.Render("enter")+t.KeyDesc.Render(" pick/review    ")+
			t.Key.Render("esc")+t.KeyDesc.Render(" cancel"))

	box := t.Dialog.Width(inner).Render(strings.Join(lines, "\n"))
	return placeCenter(box, width, height)
}

// renderChoice draws a choice field with its cycling arrows.
func renderChoice(t theme.Theme, field formField, active bool, width int) string {
	value := ui.Truncate(field.value(), width-4)
	if active {
		return t.Accent.Render("‹ ") + t.Base.Render(value) + t.Accent.Render(" ›")
	}
	return t.Base.Render("  " + value)
}

// renderIdleText draws a text field that does not have focus.
func renderIdleText(t theme.Theme, field formField, width int) string {
	value := field.value()
	if value == "" {
		return t.Muted.Render(ui.Truncate(field.input.Placeholder, width))
	}
	return t.Base.Render(ui.Truncate(value, width))
}
