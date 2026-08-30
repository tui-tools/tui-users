package shadow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tui-tools/tui-users/internal/accounts"
)

// This package is where output tui-users did not write becomes what the tool
// says about an account: `getent passwd`, `getent shadow`, `chage -l`, an
// authorized_keys file, a sudoers file, `sudo -l`. A parser that mis-reads a
// line here is how a screen ends up naming a user that is not there, or
// crediting one account with another's key. `go test` replays the seeds below
// on every commit, and `go test -fuzz=FuzzParseShadow ./internal/shadow`
// explores past them locally — see tui-kit's templates/FUZZING.md for the
// family rule.
//
// The seeds are the same captured fixtures the table tests use, so the corpus
// starts on the real line shapes and mutates from there instead of guessing
// them.

// seed adds every named testdata file to the corpus, plus the shapes a real
// capture never has: nothing, a lone separator, a truncated line.
func seed(f *testing.F, names ...string) {
	f.Helper()
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // the name is a literal in the tests, and testdata is in the repository
		if err != nil {
			f.Fatalf("read fixture %s: %v", name, err)
		}
		f.Add(string(raw))
	}
	f.Add("")
	f.Add("\n\n\n")
	f.Add(":")
	f.Add("::::::")
	f.Add("#")
}

// blank reports a string that is empty or carries only spaces: the shape that
// renders as a hole in a column and is never a name.
func blank(s string) bool { return strings.TrimSpace(s) == "" }

// ---------------------------------------------------------- the databases ---

func FuzzParsePasswd(f *testing.F) {
	seed(f, "getent-passwd.txt")
	f.Fuzz(func(t *testing.T, out string) {
		for _, user := range ParsePasswd(out) {
			if blank(user.Name) {
				t.Fatalf("account with a blank name: %#v", user)
			}
			// The name is the first colon-separated field and the key every
			// other reader joins on, so a colon in it means the line was
			// read wrong.
			if strings.ContainsAny(user.Name, ":\n") {
				t.Fatalf("account name is not one field: %q", user.Name)
			}
			// Nothing here has seen /etc/shadow yet, and a password state
			// the tool did not read must not be presented as one it did.
			if user.Password != accounts.PasswordUnknown {
				t.Fatalf("%q came out of passwd claiming %q",
					user.Name, user.Password)
			}
			_ = user.LoginShell()
			_ = Flags(user, accounts.DefaultLimits())
		}
	})
}

func FuzzParseGroup(f *testing.F) {
	seed(f, "getent-group.txt")
	f.Fuzz(func(t *testing.T, out string) {
		for _, group := range ParseGroup(out) {
			if blank(group.Name) {
				t.Fatalf("group with a blank name: %#v", group)
			}
			if strings.ContainsAny(group.Name, ":\n") {
				t.Fatalf("group name is not one field: %q", group.Name)
			}
			for _, member := range group.Members {
				// A membership list is joined with commas when it is shown
				// and split on them when it is read, so a blank member is a
				// row nobody can act on.
				if blank(member) {
					t.Fatalf("blank member of %q: %q",
						group.Name, group.Members)
				}
				if strings.ContainsAny(member, ",\n") {
					t.Fatalf("member of %q is not one name: %q",
						group.Name, member)
				}
			}
		}
	})
}

func FuzzParseShadow(f *testing.F) {
	seed(f, "getent-shadow.txt")
	f.Fuzz(func(t *testing.T, out string) {
		for name, entry := range ParseShadow(out) {
			if blank(name) {
				t.Fatalf("shadow entry keyed by nothing: %#v", entry)
			}
			switch entry.State {
			case accounts.PasswordUsable, accounts.PasswordLocked,
				accounts.PasswordEmpty, accounts.PasswordNever:
			default:
				// PasswordUnknown belongs to a shadow file that was not
				// read; a line that was read always classifies.
				t.Fatalf("%q classified as %q", name, entry.State)
			}
			if !entry.Aging.Known {
				t.Fatalf("%q read from shadow but its aging is unknown", name)
			}
			// The hash is the one thing this tool never keeps. A date
			// rendered from a day count must not carry it back out.
			for _, date := range []string{
				entry.Aging.LastChange, entry.Aging.Expires,
			} {
				if strings.ContainsAny(date, "\n:$") {
					t.Fatalf("%q has a date that is not one: %q", name, date)
				}
			}
		}
	})
}

// ------------------------------------------------------------ last logins ---

func FuzzParseLastlog(f *testing.F) {
	seed(f, "lastlog.txt", "lastlog2.txt")
	f.Fuzz(func(t *testing.T, out string) {
		for name, login := range ParseLastlog(out) {
			if blank(name) {
				t.Fatalf("login keyed by nothing: %#v", login)
			}
			checkLogin(t, name, login)
		}
	})
}

func FuzzParseLast(f *testing.F) {
	seed(f, "last.txt")
	f.Fuzz(func(t *testing.T, out string) {
		login, ok := ParseLast(out)
		if !ok {
			// A miss says nothing was read, so it must carry nothing.
			if login != (Login{}) {
				t.Fatalf("no login found but one was returned: %#v", login)
			}
			return
		}
		if login.When == "" {
			t.Fatalf("a login was found with no date: %#v", login)
		}
		// `last` prints where the login came from before the date, and that
		// is the whole reason this parser exists beside lastlog.
		if login.From == "" {
			t.Fatalf("a login was found with no origin: %#v", login)
		}
		checkLogin(t, "last", login)
	})
}

// checkLogin asserts what the account screen prints on one line.
func checkLogin(t *testing.T, name string, login Login) {
	t.Helper()
	if strings.ContainsAny(login.When+login.From, "\n\r") {
		t.Fatalf("%q has a login spanning lines: %#v", name, login)
	}
	if login.When == "" {
		return
	}
	// The date is found by looking for the weekday, so it has to start on
	// one: anything else means a column was read as a date.
	if !weekdays[strings.Fields(login.When)[0]] {
		t.Fatalf("%q has a date that does not start on a weekday: %q",
			name, login.When)
	}
}

func FuzzParseChage(f *testing.F) {
	seed(f, "chage-l.txt", "chage-l-never.txt")
	f.Fuzz(func(t *testing.T, out string) {
		aging := ParseChage(out)
		// "never" is chage's word for the absence the model carries as an
		// empty string; letting it through would print a date column reading
		// "never never".
		for _, date := range []string{aging.LastChange, aging.Expires} {
			if strings.EqualFold(date, "never") {
				t.Fatalf("chage's \"never\" survived into %#v", aging)
			}
			// It is printed in a column beside the account, so it is a
			// value rather than a label with one still attached.
			if date != strings.TrimSpace(date) {
				t.Fatalf("date is not trimmed: %q", date)
			}
		}
		_ = aging.NoExpiry()
	})
}

// -------------------------------------------------------------------- ssh ---

func FuzzParseAuthorizedKeys(f *testing.F) {
	seed(f, "authorized_keys")
	f.Fuzz(func(t *testing.T, raw string) {
		lines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
		keys := ParseAuthorizedKeys(raw)
		for _, key := range keys {
			// Removing a key rewrites the file without that line number, so
			// a line number that does not point back at the key is the one
			// mistake this parser cannot afford.
			if key.Line < 1 || key.Line > len(lines) {
				t.Fatalf("key on line %d of a %d-line file",
					key.Line, len(lines))
			}
			if lines[key.Line-1] != key.Raw {
				t.Fatalf("line %d is %q but the key carries %q",
					key.Line, lines[key.Line-1], key.Raw)
			}
			if blank(key.Type) {
				t.Fatalf("key with no type: %#v", key)
			}
			if strings.ContainsAny(key.Type, " \t\n") {
				t.Fatalf("key type is not one field: %q", key.Type)
			}
		}
		// ssh-keygen's lines are zipped on by position, so a count that does
		// not match must leave every key as it was.
		zipped := ParseFingerprints("", keys)
		if len(zipped) != len(keys) {
			t.Fatalf("zipping %d fingerprints onto %d keys returned %d",
				0, len(keys), len(zipped))
		}
	})
}

func FuzzParseFingerprints(f *testing.F) {
	seed(f, "ssh-keygen-l.txt")
	f.Fuzz(func(t *testing.T, out string) {
		for _, count := range []int{0, 1, 3} {
			keys := make([]accounts.Key, count)
			for i := range keys {
				keys[i] = accounts.Key{Type: "ssh-ed25519", Line: i + 1}
			}
			got := ParseFingerprints(out, keys)
			if len(got) != count {
				t.Fatalf("%d keys in, %d out", count, len(got))
			}
			for _, key := range got {
				// A fingerprint is what a reader compares against the one on
				// the laptop, so a half-read one would be worse than none.
				if key.Fingerprint == "" {
					continue
				}
				if !strings.Contains(key.Fingerprint, ":") {
					t.Fatalf("not a fingerprint: %q", key.Fingerprint)
				}
				if strings.ContainsAny(key.Fingerprint, " \t\n") {
					t.Fatalf("fingerprint is not one field: %q",
						key.Fingerprint)
				}
			}
		}
	})
}

// ------------------------------------------------------------------ sudo ---

func FuzzParseSudoers(f *testing.F) {
	seed(f, "sudoers.txt")
	f.Fuzz(func(t *testing.T, raw string) {
		lines := strings.Split(raw, "\n")
		file := ParseSudoers("/etc/sudoers", raw)
		if file.Raw != raw {
			t.Fatalf("the file was not quoted back verbatim")
		}
		for _, entry := range file.Entries {
			if entry.File != "/etc/sudoers" {
				t.Fatalf("entry attributed to %q", entry.File)
			}
			// The screen sends a reader to file:line, so the line has to be
			// the one the rule was read from.
			if entry.Line < 1 || entry.Line > len(lines) {
				t.Fatalf("rule on line %d of a %d-line file",
					entry.Line, len(lines))
			}
			if strings.TrimSpace(lines[entry.Line-1]) != entry.Text {
				t.Fatalf("line %d is %q but the rule carries %q",
					entry.Line, lines[entry.Line-1], entry.Text)
			}
			if blank(entry.Who) {
				t.Fatalf("rule with nobody in it: %#v", entry)
			}
			if entry.NoPasswd && !strings.Contains(entry.Text, "NOPASSWD") {
				t.Fatalf("rule marked NOPASSWD without saying so: %q",
					entry.Text)
			}
		}
	})
}

func FuzzParseSudoList(f *testing.F) {
	seed(f, "sudo-l.txt")
	f.Fuzz(func(t *testing.T, out string) {
		rules, noPasswd := ParseSudoList(out)
		if noPasswd && len(rules) == 0 {
			t.Fatalf("no rules, and yet one of them needs no password")
		}
		found := false
		for _, rule := range rules {
			if blank(rule) {
				t.Fatalf("blank rule in %q", rules)
			}
			if rule != strings.TrimSpace(rule) {
				t.Fatalf("rule is not trimmed: %q", rule)
			}
			if strings.Contains(rule, "NOPASSWD") {
				found = true
			}
		}
		// The flag is what the screen says about the rules it is showing, so
		// it has to be visible in one of them.
		if noPasswd != found {
			t.Fatalf("NOPASSWD reported as %v, found in the rules: %v",
				noPasswd, found)
		}
	})
}

// -------------------------------------------------------- the rest of it ---

func FuzzParseLoginctl(f *testing.F) {
	seed(f, "loginctl.txt")
	f.Fuzz(func(t *testing.T, out string) {
		for _, session := range ParseLoginctl(out) {
			// The id is what `loginctl terminate-session` is given.
			if blank(session.ID) {
				t.Fatalf("session with no id: %#v", session)
			}
			if blank(session.User) {
				t.Fatalf("session belonging to nobody: %#v", session)
			}
			for _, field := range []string{
				session.ID, session.User, session.TTY, session.Type,
				session.Remote,
			} {
				if strings.ContainsAny(field, " \t\n") {
					t.Fatalf("session field is not one column: %q", field)
				}
			}
		}
	})
}

func FuzzParseLoginDefs(f *testing.F) {
	seed(f, "login.defs.txt")
	f.Fuzz(func(t *testing.T, raw string) {
		limits := ParseLoginDefs(raw)
		// Human() is what decides a person's account from a service one, and
		// every flag on the list screen is built on that answer.
		for _, uid := range []int{0, 999, 1000, 60000, 65534} {
			_ = limits.Human(uid)
		}
		// A file that sets nothing leaves the family's defaults in place: a
		// tool that read no limits must not invent narrower ones.
		if raw == "" && limits != accounts.DefaultLimits() {
			t.Fatalf("an empty login.defs changed the defaults: %#v", limits)
		}
	})
}

func FuzzParseShells(f *testing.F) {
	seed(f, "shells.txt")
	f.Fuzz(func(t *testing.T, raw string) {
		seen := map[string]bool{}
		for _, shell := range ParseShells(raw) {
			// The list is what the shell picker offers, and what it offers
			// is written into /etc/passwd: an absolute path, once.
			if !strings.HasPrefix(shell, "/") {
				t.Fatalf("shell is not an absolute path: %q", shell)
			}
			if shell != strings.TrimSpace(shell) {
				t.Fatalf("shell is not trimmed: %q", shell)
			}
			if seen[shell] {
				t.Fatalf("shell offered twice: %q", shell)
			}
			seen[shell] = true
		}
	})
}

func FuzzParseSemanageLogin(f *testing.F) {
	seed(f, "semanage-login.txt")
	f.Fuzz(func(t *testing.T, out string) {
		for login, seuser := range ParseSemanageLogin(out) {
			if blank(login) || blank(seuser) {
				t.Fatalf("mapping %q => %q", login, seuser)
			}
			if strings.ContainsAny(login+seuser, " \t\n") {
				t.Fatalf("mapping is not two columns: %q => %q",
					login, seuser)
			}
		}
	})
}
