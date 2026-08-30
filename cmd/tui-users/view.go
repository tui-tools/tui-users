package main

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-users/internal/accounts"
)

// Layout constants: the rows the table cannot use.
const (
	headerLines = 2
	footerLines = 2
	// minTableHeight keeps at least one visible row on a very short terminal.
	minTableHeight = 1
)

// tableHeight is the number of rows that fit on screen.
func (a *app) tableHeight() int {
	// header + table header + footer + status line.
	return max(a.height-headerLines-footerLines-2, minTableHeight)
}

// detailHeight is the number of detail lines that fit on screen.
func (a *app) detailHeight() int {
	return max(a.height-headerLines-footerLines-1, minTableHeight)
}

// View renders the whole screen.
func (a *app) View() string {
	switch a.mode {
	case modeConfirm:
		return a.confirm.View(a.theme, a.width, a.height)
	case modeFilter, modeInput:
		return a.input.View(a.theme, a.width, a.height)
	case modePicker:
		return a.picker.View(a.theme, a.width, a.height)
	case modeForm:
		return a.form.view(a.theme, a.width, a.height)
	case modeHelp:
		return placeCenter(
			ui.HelpScreen(a.theme, "tui-users — keys", helpKeys(), a.width),
			a.width, a.height)
	case modeUserDetail:
		return a.scrollView(a.detail.Name, a.userDetailLines(), a.detailHelpKeys())
	case modeGroupDetail:
		return a.scrollView("group "+a.group.Name, a.groupDetailLines(),
			a.groupDetailHelpKeys())
	case modeGroups:
		return a.listView(a.groupsTable(), len(a.visibleGroups),
			len(a.model.Groups), "groups", a.groupsHelpKeys())
	case modeSudoers:
		return a.listView(a.sudoersTable(), len(a.visibleRules),
			a.ruleCount(), "sudo rules", a.sudoersHelpKeys())
	}
	return a.usersView()
}

// placeCenter centers a rendered box in the terminal.
func placeCenter(box string, width, height int) string {
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

// usersView renders the accounts screen.
func (a *app) usersView() string {
	var body string
	switch {
	case a.loading && len(a.visibleUsers) == 0:
		body = ui.EmptyState(a.theme, "reading the accounts…",
			a.width, a.tableHeight()+1)
	case len(a.visibleUsers) == 0 && a.filter != "":
		body = ui.EmptyState(a.theme,
			"no account matches "+strconv.Quote(a.filter),
			a.width, a.tableHeight()+1)
	case len(a.visibleUsers) == 0 && a.loadFailed:
		body = ui.EmptyState(a.theme,
			"could not read the accounts — see the message below",
			a.width, a.tableHeight()+1)
	case len(a.visibleUsers) == 0:
		body = ui.EmptyState(a.theme, "this machine reports no accounts",
			a.width, a.tableHeight()+1)
	default:
		body = a.usersTable()
	}
	return a.listView(body, len(a.visibleUsers), len(a.model.Users),
		"accounts", a.shortHelpKeys())
}

// listView is the frame every list screen shares: header, body, hint bar and
// status line.
func (a *app) listView(body string, shown, total int, what string,
	hints []ui.KeyHint) string {
	header := a.headerView("")
	help := ui.HelpBar(a.theme, hints, a.width)
	status := ui.StatusLine(a.theme, a.statusKind, a.status,
		a.defaultStatus(shown, total, what), a.width)
	return strings.Join([]string{header, body, help, status}, "\n")
}

// scrollView is the frame the two detail screens share.
func (a *app) scrollView(subtitle string, lines []string,
	hints []ui.KeyHint) string {
	header := a.headerView(subtitle)

	height := a.detailHeight()
	offset := min(a.detailOffset, max(len(lines)-height, 0))
	a.detailOffset = offset
	end := min(offset+height, len(lines))

	body := make([]string, 0, height)
	for _, line := range lines[offset:end] {
		body = append(body, a.theme.Row.Width(a.width).Render(
			ui.Truncate(line, a.width-2)))
	}
	for i := len(body); i < height; i++ {
		body = append(body, a.theme.Row.Width(a.width).Render(""))
	}

	help := ui.HelpBar(a.theme, hints, a.width)
	position := strconv.Itoa(offset+1) + "–" + strconv.Itoa(end) +
		" of " + strconv.Itoa(len(lines)) + " lines  ·  esc to go back"
	status := ui.StatusLine(a.theme, a.statusKind, a.status, position, a.width)
	return strings.Join([]string{header,
		strings.Join(body, "\n"), help, status}, "\n")
}

// headerView renders the facts at the top of every screen.
func (a *app) headerView(subtitleExtra string) string {
	t := a.theme

	shadowValue, shadowStyle := "read", t.OK
	if !a.model.ShadowRead {
		shadowValue, shadowStyle = "unreadable", t.Warn
	}
	facts := []ui.Fact{
		{Label: "accounts", Value: strconv.Itoa(len(a.model.Users))},
		{Label: "shadow", Value: shadowValue, Style: &shadowStyle},
	}

	if flagged := len(a.model.Flagged()); flagged > 0 {
		style := t.Danger
		facts = append(facts, ui.Fact{Label: "flagged",
			Value: strconv.Itoa(flagged), Style: &style})
	}
	if nopasswd := a.model.NoPasswdCount(); nopasswd > 0 {
		style := t.Warn
		facts = append(facts, ui.Fact{Label: "nopasswd",
			Value: strconv.Itoa(nopasswd), Style: &style})
	}
	// The backend version, when it was probed: quiet on a tested version,
	// coloured on one nobody has run against.
	if a.backendCompat.Backend != "" {
		facts = append(facts, ui.CompatFact(t, a.backendCompat))
	}

	subtitle := a.backend.Describe()
	if subtitleExtra != "" {
		subtitle += "  ·  " + subtitleExtra
	}
	if a.filter != "" {
		subtitle += "  ·  filter: " + a.filter
	}
	return ui.Header{Title: "tui-users", Subtitle: subtitle, Facts: facts}.
		Render(t, a.width)
}

// defaultStatus is the hint shown when there is no message to report.
func (a *app) defaultStatus(shown, total int, what string) string {
	count := strconv.Itoa(shown)
	if a.filter != "" {
		return count + " of " + strconv.Itoa(total) + " " + what +
			"  ·  ? for help"
	}
	switch a.mode {
	case modeGroups:
		return count + " " + what + "  ·  enter for members  ·  tab: sudoers"
	case modeSudoers:
		return count + " " + what + "  ·  read-only  ·  tab: accounts"
	default:
		return count + " " + what + "  ·  enter for detail  ·  tab: groups"
	}
}

// ruleCount is how many sudo rules the model holds, filter aside.
func (a *app) ruleCount() int {
	count := 0
	for _, file := range a.model.Sudoers {
		count += len(file.Entries)
	}
	return count
}

// usersTable renders the accounts list, dropping columns on narrow terminals.
func (a *app) usersTable() string {
	columns := []ui.Column{
		{Title: "USER", Width: 12, Flex: true},
		{Title: "UID", Width: 6},
		{Title: "GROUP", Width: 10},
		{Title: "PASSWORD", Width: 12},
	}
	// Progressive disclosure: extra columns only when they fit. The finding is
	// the last to go and the first thing a wide terminal shows, because it is
	// why the row is at the top.
	showShell := a.width >= 64
	showLogin := a.width >= 82
	showReason := a.width >= 96
	if showShell {
		columns = append(columns, ui.Column{Title: "SHELL", Width: 10})
	}
	if showLogin {
		columns = append(columns, ui.Column{Title: "LAST LOGIN", Width: 14})
	}
	if showReason {
		columns = append(columns, ui.Column{Title: "FINDING", Width: 20, Flex: true})
	}

	rows := make([][]string, 0, len(a.visibleUsers))
	styles := make([]*lipgloss.Style, 0, len(a.visibleUsers))
	for _, user := range a.visibleUsers {
		row := []string{
			user.Name,
			strconv.Itoa(user.UID),
			user.PrimaryGroup,
			passwordCell(user),
		}
		if showShell {
			row = append(row, shortShell(user.Shell))
		}
		if showLogin {
			row = append(row, lastLoginCell(user))
		}
		if showReason {
			row = append(row, user.Reason())
		}
		rows = append(rows, row)
		styles = append(styles, a.userStyle(user))
	}

	return ui.Table{
		Columns:  columns,
		Rows:     rows,
		Styles:   styles,
		Selected: a.users.cursor,
		Offset:   a.users.offset,
		Height:   a.tableHeight(),
	}.Render(a.theme, a.width)
}

// passwordCell renders the password column, marking the account that has sudo
// so the two facts that decide what somebody can do sit in one place.
func passwordCell(u accounts.User) string {
	cell := u.Password
	if u.Sudo.Granted() {
		cell += " +sudo"
	}
	return cell
}

// shortShell drops the directory from a shell path, which is the same for
// nearly every row and costs a column of width.
func shortShell(shell string) string {
	if i := strings.LastIndexByte(shell, '/'); i >= 0 {
		return shell[i+1:]
	}
	if shell == "" {
		return "—"
	}
	return shell
}

// lastLoginCell renders the last login, keeping the day and dropping the
// seconds nobody reads in a table.
func lastLoginCell(u accounts.User) string {
	if u.LastLogin == "" {
		return "never"
	}
	fields := strings.Fields(u.LastLogin)
	if len(fields) >= 3 {
		return strings.Join(fields[:3], " ")
	}
	return u.LastLogin
}

// userStyle colors a row by what was found on it, so an account that can take
// the machine over does not look like the one whose password is merely old.
func (a *app) userStyle(u accounts.User) *lipgloss.Style {
	var style lipgloss.Style
	switch {
	case u.Severity() == accounts.SeverityCritical:
		style = a.theme.Row.Foreground(a.theme.Danger.GetForeground())
	case u.Severity() == accounts.SeverityWarning:
		style = a.theme.Row.Foreground(a.theme.Warn.GetForeground())
	case u.Locked():
		style = a.theme.Row.Foreground(a.theme.Muted.GetForeground())
	case u.System:
		style = a.theme.Row.Foreground(a.theme.Muted.GetForeground())
	default:
		style = a.theme.Row
	}
	return &style
}

// groupsTable renders the groups list.
func (a *app) groupsTable() string {
	columns := []ui.Column{
		{Title: "GROUP", Width: 16, Flex: true},
		{Title: "GID", Width: 7},
		{Title: "MEMBERS", Width: 8},
	}
	showList := a.width >= 60
	if showList {
		columns = append(columns, ui.Column{Title: "WHO", Width: 30, Flex: true})
	}

	rows := make([][]string, 0, len(a.visibleGroups))
	styles := make([]*lipgloss.Style, 0, len(a.visibleGroups))
	for _, group := range a.visibleGroups {
		members := group.All()
		row := []string{group.Name, strconv.Itoa(group.GID),
			strconv.Itoa(len(members))}
		if showList {
			row = append(row, strings.Join(members, " "))
		}
		rows = append(rows, row)
		style := a.theme.Row
		if group.System {
			style = a.theme.Row.Foreground(a.theme.Muted.GetForeground())
		}
		styles = append(styles, &style)
	}
	if len(rows) == 0 {
		return ui.EmptyState(a.theme, "no group matches", a.width, a.tableHeight()+1)
	}

	return ui.Table{
		Columns: columns, Rows: rows, Styles: styles,
		Selected: a.groups.cursor, Offset: a.groups.offset,
		Height: a.tableHeight(),
	}.Render(a.theme, a.width)
}

// sudoersTable renders the sudo rules, which are read-only in v0.1.
func (a *app) sudoersTable() string {
	if len(a.visibleRules) == 0 {
		message := "no sudo rule was read"
		if a.model.SudoersNote != "" {
			message = a.model.SudoersNote
		}
		return ui.EmptyState(a.theme, message, a.width, a.tableHeight()+1)
	}

	columns := []ui.Column{
		{Title: "WHO", Width: 14, Flex: true},
		{Title: "RULE", Width: 30, Flex: true},
	}
	showFile := a.width >= 76
	if showFile {
		columns = append(columns,
			ui.Column{Title: "FILE", Width: 28, Flex: true},
			ui.Column{Title: "LINE", Width: 5})
	}

	rows := make([][]string, 0, len(a.visibleRules))
	styles := make([]*lipgloss.Style, 0, len(a.visibleRules))
	for _, entry := range a.visibleRules {
		row := []string{entry.Who, ruleText(entry)}
		if showFile {
			row = append(row, entry.File, strconv.Itoa(entry.Line))
		}
		rows = append(rows, row)
		style := a.theme.Row
		if entry.NoPasswd {
			style = a.theme.Row.Foreground(a.theme.Warn.GetForeground())
		}
		styles = append(styles, &style)
	}

	return ui.Table{
		Columns: columns, Rows: rows, Styles: styles,
		Selected: a.rules.cursor, Offset: a.rules.offset,
		Height: a.tableHeight(),
	}.Render(a.theme, a.width)
}

// ruleText renders the rule without repeating who it applies to, which is
// already the first column.
func ruleText(entry accounts.SudoersEntry) string {
	return strings.TrimSpace(strings.TrimPrefix(entry.Text, entry.Who))
}

// userDetailLines builds the per-account screen, section by section. It
// returns plain strings so the screen can be scrolled and width-truncated in
// one place.
func (a *app) userDetailLines() []string {
	user := a.detail
	lines := []string{
		"Account " + user.Name + "  (uid " + strconv.Itoa(user.UID) + ")",
		"",
		"  full name      " + orNone(user.GECOS),
		"  primary group  " + orNone(user.PrimaryGroup) +
			" (gid " + strconv.Itoa(user.GID) + ")",
		"  groups         " + orNone(strings.Join(user.Groups, " ")),
		"  shell          " + orNone(user.Shell) + loginShellSuffix(user),
		"  home           " + orNone(user.Home),
		"  kind           " + accountKind(user, a.model.Limits),
		"  password       " + user.Password + passwordSuffix(user),
		"  last login     " + orNone(user.LastLogin) + fromSuffix(user),
	}
	if user.SELinuxLogin != "" {
		lines = append(lines, "  selinux login  "+user.SELinuxLogin+
			" (read-only here)")
	}

	if len(user.Flags) > 0 {
		lines = append(lines, "", "Findings")
		for _, flag := range user.Flags {
			lines = append(lines, "  "+flag.Severity+": "+flag.Reason)
		}
	}

	lines = append(lines, "", "Password and expiry")
	if !user.Aging.Known {
		lines = append(lines, "  (unknown: /etc/shadow needs root to read)")
	} else {
		lines = append(lines,
			"  last change    "+orNone(user.Aging.LastChange),
			"  account expiry "+orDash(user.Aging.Expires, "never"),
			"  max age        "+daysOrNever(user.Aging.MaxDays),
			"  min age        "+daysOrNever(user.Aging.MinDays),
			"  warn           "+daysOrNever(user.Aging.WarnDays))
	}

	lines = append(lines, "", "Authorized keys")
	switch {
	case user.KeysNote != "":
		lines = append(lines, "  ("+user.KeysNote+")")
	case !user.Detailed:
		lines = append(lines, "  (reading…)")
	case len(user.Keys) == 0:
		lines = append(lines, "  (none in "+orNone(user.KeysPath)+")")
	default:
		lines = append(lines, "  "+user.KeysPath)
		for _, key := range user.Keys {
			line := "  " + strconv.Itoa(key.Line) + ": " + key.Type
			if key.Bits > 0 {
				line += " " + strconv.Itoa(key.Bits)
			}
			if key.Fingerprint != "" {
				line += " " + key.Fingerprint
			}
			if key.Comment != "" {
				line += "  " + key.Comment
			}
			if key.Options != "" {
				line += "  [" + key.Options + "]"
			}
			lines = append(lines, line)
		}
	}

	lines = append(lines, "", "sudo")
	if len(user.Sudo.Groups) > 0 {
		lines = append(lines, "  member of      "+
			strings.Join(user.Sudo.Groups, ", "))
	}
	switch {
	case len(user.Sudo.Rules) > 0:
		for _, rule := range user.Sudo.Rules {
			lines = append(lines, "  "+rule)
		}
	case user.Sudo.Note != "":
		lines = append(lines, "  ("+user.Sudo.Note+")")
	case !user.Detailed:
		lines = append(lines, "  (reading…)")
	default:
		lines = append(lines, "  (nothing)")
	}

	lines = append(lines, "", "Sessions")
	sessions := user.Sessions
	if len(sessions) == 0 {
		sessions = a.model.SessionsFor(user.Name)
	}
	if len(sessions) == 0 {
		lines = append(lines, "  (not logged in)")
	}
	for _, session := range sessions {
		line := "  session " + session.ID
		if session.TTY != "" {
			line += " on " + session.TTY
		}
		if session.Remote != "" {
			line += " from " + session.Remote
		}
		if session.Type != "" {
			line += " (" + session.Type + ")"
		}
		lines = append(lines, line)
	}
	return lines
}

// groupDetailLines builds the members screen of one group. Which members are
// primary is the part `getent group` does not tell you, and the part people
// get wrong.
func (a *app) groupDetailLines() []string {
	group := a.group
	lines := []string{
		"Group " + group.Name + "  (gid " + strconv.Itoa(group.GID) + ")",
		"",
		"  kind           " + systemOrHuman(group.System),
		"  members        " + strconv.Itoa(len(group.All())),
		"",
		"Members",
	}
	if len(group.All()) == 0 {
		lines = append(lines, "  (none)")
	}
	primary := map[string]bool{}
	for _, name := range group.Primary {
		primary[name] = true
	}
	for _, name := range group.All() {
		suffix := "  supplementary"
		if primary[name] {
			suffix = "  primary group of this account"
		}
		lines = append(lines, "  "+name+suffix)
	}
	return lines
}

// accountKind says whether an account is a person's or a service's, and by
// which rule — the UID ranges are a machine's own, from /etc/login.defs.
func accountKind(u accounts.User, limits accounts.Limits) string {
	if u.System {
		return "system account (uid outside " + strconv.Itoa(limits.UIDMin) +
			"–" + strconv.Itoa(limits.UIDMax) + ")"
	}
	return "human account (uid within " + strconv.Itoa(limits.UIDMin) +
		"–" + strconv.Itoa(limits.UIDMax) + ")"
}

// systemOrHuman names a group's kind.
func systemOrHuman(system bool) string {
	if system {
		return "system group"
	}
	return "human group"
}

// passwordSuffix explains what a password state means where the word alone is
// not enough.
func passwordSuffix(u accounts.User) string {
	switch u.Password {
	case accounts.PasswordLocked:
		return " (\"!\" before the hash; keys still work)"
	case accounts.PasswordEmpty:
		return " (no password is asked for at all)"
	case accounts.PasswordNever:
		return " (no password was ever set)"
	case accounts.PasswordUnknown:
		return " (/etc/shadow needs root to read)"
	}
	return ""
}

// loginShellSuffix marks a shell that cannot start a session.
func loginShellSuffix(u accounts.User) string {
	if u.LoginShell() {
		return ""
	}
	return "  (no interactive login)"
}

// fromSuffix appends where the last login came from.
func fromSuffix(u accounts.User) string {
	if u.LastLoginFrom == "" {
		return ""
	}
	return "  from " + u.LastLoginFrom
}

// daysOrNever renders one of chage's day counts.
func daysOrNever(days int) string {
	if days < 0 || days >= 99999 {
		return "never"
	}
	return strconv.Itoa(days) + " days"
}

// orNone renders an empty value as a visible placeholder, so a blank line is
// never mistaken for a missing read.
func orNone(value string) string {
	if strings.TrimSpace(value) == "" {
		return "—"
	}
	return value
}

// orDash renders an empty value as a chosen word.
func orDash(value, empty string) string {
	if strings.TrimSpace(value) == "" {
		return empty
	}
	return value
}

// dialogDiffLines is the most diff the confirm dialog will show. The kit's
// dialog does not scroll, so a diff longer than the terminal would push its
// own title and the command preview off the screen — and the command preview
// is the one thing that must never be missed.
const dialogDiffLines = 12

// diffForDialog trims a diff to what fits above the command preview, saying
// how much was left out. A key is one long line, so the trim is by line and
// the truncation the dialog itself does handles the width.
func (a *app) diffForDialog(diff string) string {
	if strings.TrimSpace(diff) == "" {
		return "No change: the file already reads exactly like this."
	}
	budget := max(min(a.height-12, dialogDiffLines), 4)
	lines := strings.Split(strings.TrimSuffix(diff, "\n"), "\n")
	if len(lines) <= budget {
		return diff
	}
	kept := append([]string{}, lines[:budget]...)
	return strings.Join(kept, "\n") + "\n… " +
		strconv.Itoa(len(lines)-budget) + " more diff lines"
}

// shortHelpKeys is the single-line hint bar of the accounts screen.
func (a *app) shortHelpKeys() []ui.KeyHint {
	hints := []ui.KeyHint{{Key: "enter", Desc: "detail"}}
	if a.caps.SupportsCreate {
		hints = append(hints, ui.KeyHint{Key: "n", Desc: "new"})
	}
	if a.caps.SupportsLock {
		hints = append(hints, ui.KeyHint{Key: "l", Desc: "lock"})
	}
	if a.caps.SupportsPassword {
		hints = append(hints, ui.KeyHint{Key: "p", Desc: "password"})
	}
	if a.caps.SupportsGroups {
		hints = append(hints, ui.KeyHint{Key: "a", Desc: "add to group"})
	}
	return append(hints,
		ui.KeyHint{Key: "tab", Desc: "groups"},
		ui.KeyHint{Key: "/", Desc: "filter"},
		ui.KeyHint{Key: "?", Desc: "help"},
		ui.KeyHint{Key: "q", Desc: "quit"})
}

// detailHelpKeys is the hint bar of the account screen.
func (a *app) detailHelpKeys() []ui.KeyHint {
	var hints []ui.KeyHint
	if a.caps.SupportsLock {
		hints = append(hints, ui.KeyHint{Key: "l", Desc: "lock"})
	}
	if a.caps.SupportsPassword {
		hints = append(hints, ui.KeyHint{Key: "p", Desc: "password"})
	}
	if a.caps.SupportsGroups {
		hints = append(hints,
			ui.KeyHint{Key: "a", Desc: "add to group"},
			ui.KeyHint{Key: "x", Desc: "remove"})
	}
	if a.caps.SupportsShell {
		hints = append(hints, ui.KeyHint{Key: "s", Desc: "shell"})
	}
	if a.caps.SupportsExpiry {
		hints = append(hints, ui.KeyHint{Key: "e", Desc: "expiry"})
	}
	if a.caps.SupportsKeys {
		hints = append(hints, ui.KeyHint{Key: "K", Desc: "keys"})
	}
	return append(hints,
		ui.KeyHint{Key: "D", Desc: "delete"},
		ui.KeyHint{Key: "esc", Desc: "back"})
}

// groupsHelpKeys is the hint bar of the groups screen.
func (a *app) groupsHelpKeys() []ui.KeyHint {
	return []ui.KeyHint{
		{Key: "enter", Desc: "members"},
		{Key: "tab", Desc: "sudoers"},
		{Key: "/", Desc: "filter"},
		{Key: "R", Desc: "reload"},
		{Key: "?", Desc: "help"},
		{Key: "q", Desc: "quit"},
	}
}

// groupDetailHelpKeys is the hint bar of one group's members.
func (a *app) groupDetailHelpKeys() []ui.KeyHint {
	return []ui.KeyHint{
		{Key: "↑/↓", Desc: "scroll"},
		{Key: "esc", Desc: "back"},
		{Key: "?", Desc: "help"},
	}
}

// sudoersHelpKeys is the hint bar of the sudoers screen.
func (a *app) sudoersHelpKeys() []ui.KeyHint {
	return []ui.KeyHint{
		{Key: "tab", Desc: "accounts"},
		{Key: "/", Desc: "filter"},
		{Key: "R", Desc: "reload"},
		{Key: "?", Desc: "help"},
		{Key: "q", Desc: "quit"},
	}
}

// helpKeys is the full key list shown on the help screen.
func helpKeys() []ui.KeyHint {
	return []ui.KeyHint{
		{Key: "tab / shift+tab", Desc: "accounts, groups, sudo rules"},
		{Key: "↑/k, ↓/j", Desc: "move the selection, or scroll a detail screen"},
		{Key: "g / G", Desc: "first / last row"},
		{Key: "pgup/pgdn", Desc: "scroll a page"},
		{Key: "enter", Desc: "open the selected account or group"},
		{Key: "esc", Desc: "leave the detail screen"},
		{Key: "/", Desc: "filter the current screen (esc clears)"},
		{Key: "n", Desc: "create an account"},
		{Key: "D", Desc: "delete the account, with or without its home"},
		{Key: "l", Desc: "lock or unlock the account's password"},
		{Key: "p", Desc: "set a password (never echoed, never in an argv)"},
		{Key: "a / x", Desc: "add to a group / remove from one"},
		{Key: "s", Desc: "change the login shell"},
		{Key: "e", Desc: "set the account expiry and password lifetime"},
		{Key: "K", Desc: "add an authorized key, or remove one of them"},
		{Key: "R", Desc: "re-read the accounts"},
		{Key: "?", Desc: "this help"},
		{Key: "q", Desc: "quit"},
		{Key: "", Desc: ""},
		{Key: "note", Desc: "every change is previewed and confirmed first"},
		{Key: "note", Desc: "the keys of an account are read when you open it"},
		{Key: "note", Desc: "sudo rules are read-only: edit them with visudo"},
	}
}
