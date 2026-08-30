package shadow

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tui-tools/tui-users/internal/accounts"
)

// secondsPerDay converts the day counts /etc/shadow stores into a date. Every
// aging field in that file is "days since 1970-01-01", which is why a raw
// shadow line is unreadable and this tool renders dates instead.
const secondsPerDay = 24 * 60 * 60

// ParsePasswd reads `getent passwd` — name:x:uid:gid:gecos:home:shell — into
// accounts. getent is used rather than /etc/passwd because it answers for
// every NSS source the machine has, so a machine with LDAP or systemd-homed
// accounts is read the same way as one with only local files.
func ParsePasswd(out string) []accounts.User {
	var users []accounts.User
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(strings.TrimRight(line, "\r"), ":")
		if len(fields) < 7 || fields[0] == "" {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		gid, err := strconv.Atoi(fields[3])
		if err != nil {
			continue
		}
		users = append(users, accounts.User{
			Name:     fields[0],
			UID:      uid,
			GID:      gid,
			GECOS:    fields[4],
			Home:     fields[5],
			Shell:    fields[6],
			Password: accounts.PasswordUnknown,
		})
	}
	return users
}

// ParseGroup reads `getent group` — name:x:gid:member,member — into groups.
func ParseGroup(out string) []accounts.Group {
	var groups []accounts.Group
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(strings.TrimRight(line, "\r"), ":")
		if len(fields) < 4 || fields[0] == "" {
			continue
		}
		gid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		group := accounts.Group{Name: fields[0], GID: gid}
		for _, member := range strings.Split(fields[3], ",") {
			if member = strings.TrimSpace(member); member != "" {
				group.Members = append(group.Members, member)
			}
		}
		groups = append(groups, group)
	}
	return groups
}

// ShadowEntry is one line of /etc/shadow, decoded. The hash itself is never
// kept: what the tool needs from it is whether it is a password, a lock or
// nothing at all.
type ShadowEntry struct {
	// State is one of the accounts.Password* constants.
	State string
	Aging accounts.Aging
}

// ParseShadow reads `getent shadow` into per-account password state and aging.
// Reading it needs root, so a machine where this returns nothing is a normal
// unprivileged run, not a failure.
//
// The second field is the whole answer to "can this account be logged into
// with a password":
//
//	""        no password at all — anybody who reaches a prompt is in
//	"!" "!!"  no usable password; "!" in front of a hash is a lock
//	"*"       password authentication disabled, the service-account default
//	"$6$…"    a hash
func ParseShadow(out string) map[string]ShadowEntry {
	entries := map[string]ShadowEntry{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(strings.TrimRight(line, "\r"), ":")
		if len(fields) < 9 || fields[0] == "" {
			continue
		}
		entry := ShadowEntry{State: passwordState(fields[1])}
		entry.Aging = accounts.Aging{
			Known:      true,
			LastChange: dayField(fields[2]),
			MinDays:    intField(fields[3]),
			MaxDays:    intField(fields[4]),
			WarnDays:   intField(fields[5]),
			Inactive:   intField(fields[6]),
			Expires:    dayField(fields[7]),
		}
		entries[fields[0]] = entry
	}
	return entries
}

// passwordState classifies the hash field.
func passwordState(hash string) string {
	switch {
	case hash == "":
		return accounts.PasswordEmpty
	case hash == "*" || hash == "!!" || hash == "!" || hash == "*LK*":
		return accounts.PasswordNever
	case strings.HasPrefix(hash, "!") || strings.HasPrefix(hash, "*LK*"):
		return accounts.PasswordLocked
	default:
		return accounts.PasswordUsable
	}
}

// intField reads a shadow number, returning -1 for the empty field that means
// "no policy".
func intField(value string) int {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return -1
	}
	return n
}

// dayField renders a "days since the epoch" field as a date. An empty field
// and a negative one both mean "never", which is rendered as an empty string
// so the UI decides how to say it.
func dayField(value string) string {
	days := intField(value)
	if days < 0 {
		return ""
	}
	if days == 0 {
		// 0 in the last-change field means "must change at next login", which
		// is not a date and must not be printed as 1970-01-01.
		return "at next login"
	}
	return time.Unix(int64(days)*secondsPerDay, 0).UTC().Format("2006-01-02")
}

// weekdays are how both lastlog and last start a date, which is what tells the
// date apart from the port and the host in a column layout that shifts with
// the length of a user name.
var weekdays = map[string]bool{
	"Mon": true, "Tue": true, "Wed": true, "Thu": true,
	"Fri": true, "Sat": true, "Sun": true,
}

// Login is the last login of one account.
type Login struct {
	// When is the timestamp as the machine's own tool rendered it, or empty
	// for an account that has never logged in.
	When string
	// From is the terminal or the remote host.
	From string
}

// ParseLastlog reads the table `lastlog` and `lastlog2` both print:
//
//	Username         Port     From             Latest
//	root             pts/0                     Fri Aug 29 09:12:01 -0300 2026
//	alice                                      **Never logged in**
//
// The columns are padded to a fixed width until a name is longer than the
// field, so the date is found by looking for the weekday rather than by
// counting characters.
func ParseLastlog(out string) map[string]Login {
	logins := map[string]Login{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] == "Username" {
			continue
		}
		name := fields[0]
		rest := fields[1:]
		if strings.Contains(line, "Never logged in") {
			logins[name] = Login{}
			continue
		}
		date := -1
		for i, field := range rest {
			if weekdays[field] {
				date = i
				break
			}
		}
		if date < 0 {
			continue
		}
		login := Login{When: strings.Join(rest[date:], " ")}
		if from := rest[:date]; len(from) > 0 {
			login.From = strings.Join(from, " ")
		}
		logins[name] = login
	}
	return logins
}

// ParseLast reads the first line of `last -n1 -w <user>`:
//
//	alice    pts/1        192.0.2.10       Fri Aug 29 10:02   still logged in
//
// It is the second source for a last login, and the one that knows where the
// login came from on a machine whose lastlog database was never written.
func ParseLast(out string) (Login, bool) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] == "wtmp" || fields[0] == "btmp" {
			continue
		}
		date := -1
		for i, field := range fields {
			if weekdays[field] {
				date = i
				break
			}
		}
		if date < 2 {
			continue
		}
		return Login{
			When: strings.Join(fields[date:], " "),
			From: strings.Join(fields[1:date], " "),
		}, true
	}
	return Login{}, false
}

// ParseChage reads `chage -l <user>`, which is the human rendering of the
// aging fields of /etc/shadow and needs root for anyone but the account
// itself. Its labels are stable across shadow-utils releases; its dates are
// locale-dependent, which is why the backend runs it with LC_ALL=C.
func ParseChage(out string) accounts.Aging {
	aging := accounts.Aging{MinDays: -1, MaxDays: -1, WarnDays: -1, Inactive: -1}
	for _, line := range strings.Split(out, "\n") {
		label, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		label = strings.ToLower(strings.TrimSpace(label))
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		aging.Known = true
		switch {
		case strings.HasPrefix(label, "last password change"):
			aging.LastChange = neverToEmpty(value)
		case strings.HasPrefix(label, "account expires"):
			aging.Expires = neverToEmpty(value)
		case strings.HasPrefix(label, "maximum number of days"):
			aging.MaxDays = intField(value)
		case strings.HasPrefix(label, "minimum number of days"):
			aging.MinDays = intField(value)
		case strings.HasPrefix(label, "number of days of warning"):
			aging.WarnDays = intField(value)
		case strings.HasPrefix(label, "password inactive"):
			if value != "never" {
				aging.Inactive = intField(value)
			}
		}
	}
	return aging
}

// neverToEmpty turns chage's word for "no expiry" into the absence the model
// carries.
func neverToEmpty(value string) string {
	if strings.EqualFold(value, "never") {
		return ""
	}
	return value
}

// ParseAuthorizedKeys reads an authorized_keys file into keys, keeping the
// line number of each one — which is what a removal rewrites the file without.
//
// A line carrying options ("no-pty,command=…") is kept as a key with those
// options recorded: the tool will not write one, but it must show the ones
// that are there, because a restricted key is exactly the kind of thing
// somebody wants to find.
func ParseAuthorizedKeys(raw string) []accounts.Key {
	var keys []accounts.Key
	for i, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key := accounts.Key{Line: i + 1, Raw: line}
		fields := strings.Fields(trimmed)
		// A line that starts with something other than a key type carries
		// options, and the key type is the next field.
		start := 0
		if !keyTypeRe.MatchString(fields[0]) && len(fields) > 1 {
			key.Options = fields[0]
			start = 1
		}
		if start >= len(fields) {
			continue
		}
		key.Type = fields[start]
		if len(fields) > start+2 {
			key.Comment = strings.Join(fields[start+2:], " ")
		}
		keys = append(keys, key)
	}
	return keys
}

// ParseFingerprints reads `ssh-keygen -lf`, one line per key:
//
//	256 SHA256:2p0k…  alice@laptop (ED25519)
//
// The lines come back in file order, so they are zipped onto the parsed keys
// by position. A count that does not match means ssh-keygen skipped something,
// and rather than guess which one, no fingerprint is attached at all.
func ParseFingerprints(out string, keys []accounts.Key) []accounts.Key {
	var bits []int
	var prints []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.Contains(fields[1], ":") {
			continue
		}
		size, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		bits = append(bits, size)
		prints = append(prints, fields[1])
	}
	if len(prints) != len(keys) {
		return keys
	}
	for i := range keys {
		keys[i].Bits = bits[i]
		keys[i].Fingerprint = prints[i]
	}
	return keys
}

// keyTypeRe is what an authorized_keys line starts with when it carries no
// options.
var keyTypeRe = regexp.MustCompile(`^(sk-)?(ssh|ecdsa|rsa|dsa|ed25519)`)

// ParseSudoers reads one sudoers file into the rules a reader cares about:
// who, what, and whether it runs without a password.
//
// It is a reader, not a parser of the whole grammar. Aliases, Defaults lines
// and includes are shown as they are written and not interpreted, because a
// tool that half-understood sudoers would be more dangerous than one that
// admits it is quoting the file.
func ParseSudoers(filePath, raw string) accounts.SudoersFile {
	file := accounts.SudoersFile{Path: filePath, Raw: raw}
	for i, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "Defaults") ||
			strings.HasPrefix(trimmed, "@include") ||
			strings.HasSuffix(trimmed, "_Alias") ||
			isAlias(trimmed) {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 || !strings.Contains(trimmed, "=") {
			continue
		}
		file.Entries = append(file.Entries, accounts.SudoersEntry{
			File:        filePath,
			Line:        i + 1,
			Who:         fields[0],
			Text:        trimmed,
			NoPasswd:    strings.Contains(trimmed, "NOPASSWD"),
			AllCommands: strings.HasSuffix(trimmed, "ALL"),
		})
	}
	return file
}

// isAlias reports a User_Alias / Cmnd_Alias / Host_Alias / Runas_Alias line.
func isAlias(line string) bool {
	for _, prefix := range []string{"User_Alias", "Cmnd_Alias", "Host_Alias",
		"Runas_Alias"} {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

// ParseSudoList reads `sudo -l -U <user>`, the authoritative answer to what a
// user may run — sudo's own evaluation of every rule that applies, which no
// amount of reading files can reproduce.
func ParseSudoList(out string) (rules []string, noPasswd bool) {
	collecting := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "may run the following commands") {
			collecting = true
			continue
		}
		if strings.Contains(trimmed, "is not allowed to run sudo") {
			return nil, false
		}
		if !collecting {
			continue
		}
		rules = append(rules, trimmed)
		if strings.Contains(trimmed, "NOPASSWD") {
			noPasswd = true
		}
	}
	return rules, noPasswd
}

// ParseLoginctl reads `loginctl list-sessions --no-legend`:
//
//	 3 1000 alice seat0 tty2
//	12 1000 alice      pts/3
//
// The column count has changed across systemd releases, so the parse takes the
// session id and the user by position and treats everything after them as the
// seat and the terminal.
func ParseLoginctl(out string) []accounts.Session {
	var sessions []accounts.Session
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if _, err := strconv.Atoi(fields[1]); err != nil {
			// The second column is the UID on every version that prints one;
			// a line without it is a header or a summary.
			continue
		}
		session := accounts.Session{ID: fields[0], User: fields[2]}
		for _, field := range fields[3:] {
			switch {
			case strings.HasPrefix(field, "tty"), strings.HasPrefix(field, "pts/"):
				session.TTY = field
			case strings.HasPrefix(field, "seat"):
				session.Type = field
			default:
				session.Remote = field
			}
		}
		sessions = append(sessions, session)
	}
	return sessions
}

// ParseLoginDefs reads the UID and GID ranges out of /etc/login.defs. They are
// what tells a service account from a person's, and they differ between
// distributions — Debian starts human accounts at 1000, Fedora at 1000 with a
// different system range, and a hardened machine may move both.
func ParseLoginDefs(raw string) accounts.Limits {
	limits := accounts.DefaultLimits()
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		switch fields[0] {
		case "UID_MIN":
			limits.UIDMin = value
		case "UID_MAX":
			limits.UIDMax = value
		case "SYS_UID_MIN":
			limits.SysUIDMin = value
		case "SYS_UID_MAX":
			limits.SysUIDMax = value
		case "GID_MIN":
			limits.GIDMin = value
		case "GID_MAX":
			limits.GIDMax = value
		case "PASS_MAX_DAYS":
			limits.PassMaxDays = value
		}
	}
	return limits
}

// ParseShells reads /etc/shells into the list the shell picker offers.
func ParseShells(raw string) []string {
	var shells []string
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || seen[trimmed] {
			continue
		}
		if !strings.HasPrefix(trimmed, "/") {
			continue
		}
		seen[trimmed] = true
		shells = append(shells, trimmed)
	}
	return shells
}

// ParseSemanageLogin reads `semanage login -l`, the SELinux login mapping:
//
//	Login Name    SELinux User    MLS/MCS Range    Service
//	__default__   unconfined_u    s0-s0:c0.c1023   *
//
// It is read-only here. tui-users shows which SELinux user an account maps to
// because it changes what that account can do; managing the mapping belongs to
// a tool that owns SELinux, not to this one.
func ParseSemanageLogin(out string) map[string]string {
	mapping := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] == "Login" {
			continue
		}
		mapping[fields[0]] = fields[1]
	}
	return mapping
}

// Flags decides which accounts the list shows first, and why.
//
// The rule is the family's "failed first": what is wrong with the machine
// should not have to be scrolled to. What counts as wrong here is deliberately
// narrow — four findings, each of which a competent administrator would want
// to be told about on a machine they inherited:
//
//   - a second account with UID 0, which is root under another name and does
//     not show up in `groups` or in a sudoers file;
//   - an empty password, which lets anyone who reaches a prompt log in;
//   - a service account with a login shell, which is what a compromised
//     service uses to become interactive;
//   - a person's password that never expires, which is a policy observation
//     rather than a break-in, and is ranked as one.
//
// Anything the tool cannot know it does not guess: without /etc/shadow the
// password state is unknown, and an unknown password raises no flag.
func Flags(user accounts.User, limits accounts.Limits) []accounts.Flag {
	var flags []accounts.Flag

	if user.UID == 0 && user.Name != "root" {
		flags = append(flags, accounts.Flag{
			Severity: accounts.SeverityCritical,
			Reason:   "uid 0: root under another name",
		})
	}
	if user.Password == accounts.PasswordEmpty {
		flags = append(flags, accounts.Flag{
			Severity: accounts.SeverityCritical,
			Reason:   "empty password: none is asked for",
		})
	}
	if user.UID != 0 && !limits.Human(user.UID) && user.LoginShell() {
		flags = append(flags, accounts.Flag{
			Severity: accounts.SeverityWarning,
			Reason:   "system account with a login shell",
		})
	}
	if limits.Human(user.UID) && user.Aging.Known && user.Aging.NoExpiry() &&
		user.Password == accounts.PasswordUsable {
		flags = append(flags, accounts.Flag{
			Severity: accounts.SeverityNotice,
			Reason:   "password never expires",
		})
	}
	return flags
}
