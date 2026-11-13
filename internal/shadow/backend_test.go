package shadow

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tui-tools/tui-kit/runner"
	"github.com/tui-tools/tui-users/internal/accounts"
)

// TestKeysNote covers the notes the detail screen shows in place of a key
// list. The point of the empty note is that a missing authorized_keys file is
// an answer ("nobody logs in with a key here"), not a broken read, however the
// read failed: directly, or through the escalated `cat` whose message the
// runner wraps.
func TestKeysNote(t *testing.T) {
	catFailed := func(text string) error {
		return fmt.Errorf(
			"`/usr/bin/sudo -n cat -- /home/ana/.ssh/authorized_keys` failed: %s",
			text)
	}
	cases := []struct {
		name string
		err  error
		root bool
		want string
	}{
		{
			name: "no error",
			err:  nil,
			want: "",
		},
		{
			name: "missing file, read directly",
			err:  fmt.Errorf("open: %w", fs.ErrNotExist),
			want: "",
		},
		{
			name: "missing file, read through cat",
			err: catFailed(
				"cat: /home/ana/.ssh/authorized_keys: No such file or directory"),
			want: "",
		},
		{
			name: "unreadable, read directly",
			err:  fmt.Errorf("open: %w", fs.ErrPermission),
			want: "not readable without root",
		},
		{
			name: "unreadable, read through cat",
			err: catFailed(
				"cat: /home/ana/.ssh/authorized_keys: Permission denied"),
			want: "not readable without root",
		},
		{
			name: "sudo would not run without a password",
			err: errors.New(
				"sudo needs a password: run `sudo -v` in another terminal, then retry"),
			want: "not readable without root",
		},
		{
			name: "unreadable as root keeps the failure",
			err:  catFailed("cat: /home/ana/.ssh/authorized_keys: Permission denied"),
			root: true,
			want: "`/usr/bin/sudo -n cat -- /home/ana/.ssh/authorized_keys` failed: " +
				"cat: /home/ana/.ssh/authorized_keys: Permission denied",
		},
		{
			name: "anything else is passed through, first line only",
			err:  errors.New("`cat` failed: input/output error\nand a second line"),
			want: "`cat` failed: input/output error",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := keysNote(tc.err, tc.root); got != tc.want {
				t.Errorf("keysNote() = %q, want %q", got, tc.want)
			}
		})
	}
}

// keysHome builds a home directory in a temporary directory, owned by the user
// running the test, and the account that lives in it.
func keysHome(t *testing.T) (accounts.User, string) {
	t.Helper()
	home := filepath.Join(t.TempDir(), "alice")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	user := alice
	user.Home, user.UID = home, os.Getuid()
	return user, home
}

// writeFile writes a fixture file, failing the test on error.
func writeFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// victimKeys is the file an attacker would like their key appended to.
const victimKeys = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIVictimKey000000000000 root@admin\n"

const newKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINewKeyForTheTest0000 alice@new"

// TestKeyChangesRefuseARedirectedName is the regression test for a write that
// followed the account's own symlinks with root's privileges: whatever the
// names under ~/.ssh point at, no plan is built, the other file is never read,
// and the detail screen says why instead of showing the other file's keys.
func TestKeyChangesRefuseARedirectedName(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, user *accounts.User, home string)
		want  string
	}{
		{
			name: "authorized_keys is a symlink to another account's file",
			setup: func(t *testing.T, _ *accounts.User, home string) {
				victim := filepath.Join(t.TempDir(), "authorized_keys")
				writeFile(t, victim, victimKeys)
				mustMkdir(t, filepath.Join(home, ".ssh"))
				mustSymlink(t, victim, filepath.Join(home, ".ssh", "authorized_keys"))
			},
			want: "authorized_keys is a symbolic link",
		},
		{
			name: "~/.ssh is a symlink to another account's directory",
			setup: func(t *testing.T, _ *accounts.User, home string) {
				victim := t.TempDir()
				writeFile(t, filepath.Join(victim, "authorized_keys"), victimKeys)
				mustSymlink(t, victim, filepath.Join(home, ".ssh"))
			},
			want: "/.ssh is a symbolic link",
		},
		{
			name: "authorized_keys belongs to somebody else",
			setup: func(t *testing.T, user *accounts.User, home string) {
				mustMkdir(t, filepath.Join(home, ".ssh"))
				writeFile(t, filepath.Join(home, ".ssh", "authorized_keys"), victimKeys)
				// The files belong to whoever runs the test; the account is
				// made somebody else, which is the same mismatch.
				user.UID = os.Getuid() + 1
			},
			want: "belongs to uid",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, home := keysHome(t)
			tc.setup(t, &user, home)
			backend := &Real{runners: map[string]*runner.Runner{},
				programs: ProgramNames}

			if _, err := backend.BuildAddKey(user, newKey); err == nil ||
				!strings.Contains(err.Error(), tc.want) {
				t.Errorf("BuildAddKey error = %v, want one containing %q", err, tc.want)
			}
			key := accounts.Key{Line: 1, Raw: strings.TrimSpace(victimKeys)}
			if _, err := backend.BuildRemoveKey(user, key); err == nil ||
				!strings.Contains(err.Error(), tc.want) {
				t.Errorf("BuildRemoveKey error = %v, want one containing %q", err, tc.want)
			}

			backend.loadKeys(context.Background(), &user)
			if len(user.Keys) != 0 {
				t.Errorf("the detail screen shows %d keys read through the "+
					"redirected name", len(user.Keys))
			}
			if !strings.Contains(user.KeysNote, tc.want) {
				t.Errorf("KeysNote = %q, want one containing %q", user.KeysNote, tc.want)
			}
		})
	}
}

// TestKeyChangesOnAnOrdinaryHome is the other half: an account's own ~/.ssh,
// present or not, still gets a plan, and every command in it runs as the
// account.
func TestKeyChangesOnAnOrdinaryHome(t *testing.T) {
	backend := &Real{runners: map[string]*runner.Runner{}, programs: ProgramNames}

	t.Run("no ~/.ssh yet", func(t *testing.T) {
		user, _ := keysHome(t)
		plan, err := backend.BuildAddKey(user, newKey)
		if err != nil {
			t.Fatalf("BuildAddKey: %v", err)
		}
		if len(plan.Commands) != 3 {
			t.Fatalf("%d commands, want the directory, the file and the append",
				len(plan.Commands))
		}
		assertRunAsAccount(t, user, plan.Commands)
	})

	t.Run("an existing file", func(t *testing.T) {
		user, home := keysHome(t)
		mustMkdir(t, filepath.Join(home, ".ssh"))
		existing := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOldKey00000000000000 alice@old\n"
		writeFile(t, filepath.Join(home, ".ssh", "authorized_keys"), existing)

		plan, err := backend.BuildAddKey(user, newKey)
		if err != nil {
			t.Fatalf("BuildAddKey: %v", err)
		}
		if len(plan.Commands) != 2 {
			t.Fatalf("%d commands, want the directory and the append",
				len(plan.Commands))
		}
		assertRunAsAccount(t, user, plan.Commands)
		if plan.Content != existing+newKey+"\n" {
			t.Errorf("content = %q", plan.Content)
		}

		remove, err := backend.BuildRemoveKey(user,
			accounts.Key{Line: 1, Raw: strings.TrimSpace(existing)})
		if err != nil {
			t.Fatalf("BuildRemoveKey: %v", err)
		}
		assertRunAsAccount(t, user, remove.Commands)
		if remove.TempPath != "" {
			t.Errorf("a removal staged %s, which the account cannot read",
				remove.TempPath)
		}
	})
}

// assertRunAsAccount checks that every command goes through runuser as the
// account.
func assertRunAsAccount(t *testing.T, user accounts.User, commands []accounts.Command) {
	t.Helper()
	for _, cmd := range commands {
		if len(cmd.Argv) < 5 || cmd.Argv[0] != RunAs || cmd.Argv[1] != "-u" ||
			cmd.Argv[2] != user.Name || cmd.Argv[3] != "--" {
			t.Errorf("%q does not run as %s", cmd.String(), user.Name)
		}
	}
}

func mustMkdir(t *testing.T, name string) {
	t.Helper()
	if err := os.Mkdir(name, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustSymlink(t *testing.T, target, name string) {
	t.Helper()
	if err := os.Symlink(target, name); err != nil {
		t.Fatal(err)
	}
}
